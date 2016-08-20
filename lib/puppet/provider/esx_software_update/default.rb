provider_path = Pathname.new(__FILE__).parent.parent
require 'rbvmomi'
require File.join(provider_path, 'vcenter')
require 'asm/util'

Puppet::Type.type(:esx_software_update).provide(:esx_software_update, :parent => Puppet::Provider::Vcenter) do
  @doc = "Perform software updates on a desired ESX"

  # Helper method to log an error message
  def log_error(msg, res, ex)
    Puppet.err("%s for %s: Error %s:%s " % [msg, res, ex.class, ex.message] )
    Puppet.err("Fault error message: %s" % ex.fault.errMsg.to_s) if ex.is_a?(RbVmomi::Fault)
  end

  # Method called by puppet to create a resource i.e. when exists returns false
  def create
    # Install all specified VIBs
    reboot_required = false
    installed_vibs = []
    skipped_vibs = []
    @actionable_vibs.each do |vib_url|
      begin
        install_results = install_vib vib_url
      rescue => ex
        log_error("Failed to install the VIB", vib_url, ex)
        next  # proceed to next VIB
      end
      installed_vibs += install_results[:VIBsInstalled]
      skipped_vibs += install_results[:VIBsSkipped] if install_results[:VIBsSkipped]
      reboot_required ||= install_results[:RebootRequired]
    end
    Puppet.info("Successfully installed %d VIBs" % installed_vibs.length)
    Puppet.info("Skipped installing following VIBs : %s" % skipped_vibs.join(",")) if skipped_vibs.length > 0
    # Unmount all NFS stores we mounted
    unmount_mounted_nfs_shares
    # Reboot if needed
    reboot_and_wait_for_host if reboot_required
    if installed_vibs.length + skipped_vibs.length < @actionable_vibs.length
      fail "Failed to install some or all VIBs"
    end
  end

  # Method called by puppet to remove a resource i.e. when exists returns true
  def destroy
    if @actionable_vibs.length > 0
      # Remove all specified VIBs
      reboot_required = false
      removed_vibs = []
      @actionable_vibs.each do |vib_name|
        begin
          remove_results = remove_vib vib_name
        rescue => ex
          log_error("Failed to remove VIB", vib_name, ex)
          next  # proceed to next VIB
        end
        removed_vibs += install_results[:VIBsRemoved]
        reboot_required ||= install_results[:RebootRequired]
      end
      Puppet.info("Successfully removed %d VIBs" % removed_vibs.length)
      reboot_and_wait_for_host if reboot_required
      if removed_vibs.length < @actionable_vibs.length
        fail "Failed to remove some or all VIBs"
      end
    end
  end

  # Method called by puppet to determine if a resource exists or not
  def exists?
    @actionable_vibs = []     # List of VIBs which are either a) fully qualified paths for VIBs to install,
                              # OR b) VIB package name to remove
    @mounted_nfs_shares = {}  # Map of NFS shares that are mounted on the ESX
                              # key: "nfs_hostname:/share" representing NFS mounted share
                              # value: Hash
                              #   :volume_name corresponding volume name
                              #   :new_mount   boolean indicating if it was mounted by us
    @processed_vibs = {}      # Map {id => true} of all installed, or to-be installed VIBs on the ESX host
    @unresolved_vibs = []     # List of VIBs with unresolved dependencies
                              # value: Hash
                              #   :id            VIB identifier
                              #   :dependencies  list of unresolved dependencies
                              #   :path          file path of the VIB

    fetch_mounted_nfs_shares

    fetch_installed_vibs

    vibs = resource[:vibs].is_a?(Array) ? resource[:vibs] : [resource[:vibs]]
    Puppet.debug("VIBs to query : #{vibs}...")

    # The type validation already validates proper format of fields for either install or uninstall
    # To determine the install mode, we simply need to do check if first element hash or not
    is_install = vibs.first.is_a?(Hash)

    vibs.each do |vib_data|
      unless is_install
        # For uninstall, add the VIB name to the actionable_vibs list
        @actionable_vibs.push(vib_data)
      else
        prepare_vib_for_install(vib_data)
      end
    end

    resolve_vibs

    # For install mode: if there are any actionable VIBs, we need to return false
    # (i.e. resource does not exist) so that "create" is invoked by puppet
    # For uninstall mode: if there are any actionable VIBs, we need to return true
    # (i.e. resource exist) so that "destroy" is invoked by puppet
    is_install ? @actionable_vibs.length == 0 : @actionable_vibs.length > 0
  end

  def prepare_vib_for_install(vib_data)
    # For each VIB data, mount any NFS shares if provided, then check if the VIB is already installed
    # on the ESX host. If not installed, add qualified path to the VIB to actionable_vibs list
    # Fetch VIB info from the source
    qualified_vib_path = setup_fully_qualified_vib_path(vib_data)
    begin
      vib_source_data = get_source_vib_info(qualified_vib_path)
    rescue => e
      log_error("Failed to get VIB info", qualified_vib_path, e)
      raise e
    end
    # Check if the VIB is already pre-installed. If not, we can add to actionable_vibs list
    if vib_source_data.is_a?(Array)
      vib_id = vib_source_data[0][:ID]
      unless @processed_vibs[vib_id]
        Puppet.debug("%s is not installed" % vib_id)
        unresolved_deps = process_dependencies(vib_id, vib_source_data[0][:Depends], qualified_vib_path)
        unless unresolved_deps.empty?
          Puppet.debug("%s has unresolved dependencies: %s" % [vib_id, unresolved_deps.to_s])
          @unresolved_vibs.push({:id => vib_id,
            :dependencies => unresolved_deps, :path => qualified_vib_path})
        end
      end
    end
  end

  def mark_vib_for_install(vib_id, qualified_vib_path)
    @actionable_vibs.push(qualified_vib_path)
    @processed_vibs[vib_id] = true  # Updated processed hash
  end

  def resolve_vibs
    still_unresolved = []
    Puppet.debug("Attempting to resolve %d VIBs" % @unresolved_vibs.length)
    @unresolved_vibs.each do |vib|
      unresolved_deps = process_dependencies(vib[:id], vib[:dependencies], vib[:path])
      unless unresolved_deps.empty?
        Puppet.debug("%s still has unresolved dependencies: %s" % [vib[:id], unresolved_deps.to_s])
        still_unresolved.push({:id => vib[:id], :dependencies => unresolved_deps, :path => vib[:path]})
      end
    end
    if still_unresolved.empty?
      Puppet.debug("All unresolved VIBs have been resolved")
    elsif still_unresolved.length == @unresolved_vibs.length
      Puppet.debug("Unable to resolve dependencies for %d VIBs, adding them anyways" % still_unresolved.length )
      still_unresolved.each do |vib|
        mark_vib_for_install(vib[:id], vib[:path])
      end
    else
      # Seems we were able to resolve some VIBs, it is possible the unresolved ones may resolve
      # Hence redo resolve_vibs using 'still_unresolved' list
      @unresolved_vibs = still_unresolved
      resolve_vibs
    end
  end

  # Helper method to process dependencies for given VIB, returning any unresolved dependencies
  def process_dependencies(vib_id, dependencies, qualified_vib_path)
    unresolved = []
    if dependencies && !dependencies.empty?
      dependencies.each do |dep|
        unless @processed_vibs[dep]
          unresolved << dep
        end
      end
    end
    mark_vib_for_install(vib_id, qualified_vib_path) if unresolved.empty?
    unresolved
  end

  # Helper method to reboot a ESX host and wait for it to come back upto desired timeout
  def reboot_and_wait_for_host
    host.RebootHost_Task({:force => false}).wait_for_completion
    Puppet.debug("%s Waiting upto %s seconds for host to connect" % [Time.now, resource[:reboot_timeout]])
    rounds = ((1.0 * (resource[:reboot_timeout] - 180)) / 30).ceil
    sleep 300 # Sleep to allow reboot initiation request to reflect, otherwise we may get false state of connected host
    reboot_done = false
    for i in 1..rounds
      begin
        if host.runtime.connectionState == "connected"
          Puppet.info("Host has rebooted and is connected")
          reboot_done = true
          break
        else
          Puppet.debug("%s Host connection state: %s " % [Time.now, host.runtime.connectionState] )
        end
      rescue Exception => ex
        Puppet.debug("Host is in process of rebooting, ignoring error: %s %s" % [ex.class, ex.message])
        if ex.is_a?(RbVmomi::Fault) && ex.fault.class.to_s == "NotAuthenticated"
          Puppet.info("Reset host connection")
          reset_connection
        end
      end
      sleep 30
    end
    Puppet.warning("Host not connected after rebooting in %d seconds" % resource[:reboot_timeout]) unless reboot_done
  end

  # Get fully qualified path for a given VIB, performing any setup necessary
  #
  # This method is used to perform setup operations like mounting NFS share on ESX with
  # desired volume name and return resulting fully qualified path to the VIB.
  # For HTTP(s), FTP protocols it simply uses whatever VIB path was specified.
  #
  # @param vib_data [Hash]
  # @option vib_data [String] :nfs_share Name of the NFS share on the remote NFS host
  #                            that needs to be mounted (Not required for HTTPs or FTP vib_path)
  #                            Example: /var/nfs/blah1/blah2
  # @option vib_data [String] :vib_path Fully qualified HTTP/FTP path, or relative path to NFS share (including the VIB name)
  #                           Examples:
  #                           1. http://vmwaredepot.dell.com/DEL/5.5/vib20/ASM/foo.vib
  #                           2. some_folder_relative_to_nfs_share/foo.vib
  #                           3. foo.vib (if it is directly on nfs_share folder)
  # @option vib_data [String] :volume_name Volume name to represent the mounted NFS share on ESX
  # @return [String]
  def setup_fully_qualified_vib_path(vib_data)
    return '' if vib_data.nil?
    if vib_data[:nfs_share].nil?
      # Seems we have fully qualified HTTP(s) or FTP path, use straight-away
      qualified_vib_path = vib_data[:vib_path]
    else
      if resource[:nfs_hostname].nil?
        # If there is no NFS hostname, then seems the specified Share is local to the ESX, use share + VIB as path
        qualified_vib_path = vib_data[:nfs_share] + "/" + vib_data[:vib_path]
      else
        qualified_vib_path = "/vmfs/volumes/" + vib_data[:volume_name] + "/" + vib_data[:vib_path]
        mount_key = resource[:nfs_hostname] + ":" +  vib_data[:nfs_share]
        if @mounted_nfs_shares[mount_key].nil?
          # Need to mount a new NFS store
          if mount_nfs_share(vib_data[:nfs_share], vib_data[:volume_name])
            # Add to mount map
            @mounted_nfs_shares[mount_key] = { :volume_name => vib_data[:volume_name], :new_mount => true }
          end
        end
      end
    end
    qualified_vib_path
  end

  # Helper method to get all installed VIBs and save it to our map
  def fetch_installed_vibs
    Puppet.debug("Getting list of installed VIBs...")
    cnt = 0
    host.esxcli.software.vib.get.each do |installed_vib_data|
      if installed_vib_data[:ID]
        @processed_vibs[installed_vib_data[:ID]] = installed_vib_data
        cnt += 1
      end
    end
    Puppet.debug("Found %d installed VIBs" % cnt)
  end

  # Esxcli wrapper method to get VIB info for a given VIB on either NFS, HTTP or FTP location
  def get_source_vib_info(qualified_vib_path)
    Puppet.debug("Fetching VIB info for %s" % qualified_vib_path)
    # Note: This is odd, the ESX hostagent API can handle arrays, but the VirtualCenter API does not
    if vim.serviceInstance.content.about.apiType == "HostAgent"
      host.esxcli.software.sources.vib.get({:viburl => [qualified_vib_path]})
    else # VirtualCenter
      host.esxcli.software.sources.vib.get({:viburl => qualified_vib_path})
    end
  end

  # Esxcli wrapper method to install a VIB present on either NFS, HTTP or FTP location
  def install_vib(qualified_vib_path)
    Puppet.debug("Attempting to install the VIB: %s" % qualified_vib_path)
    # Note: This is odd, the ESX hostagent API can handle arrays, but the VirtualCenter API does not
    if vim.serviceInstance.content.about.apiType == "HostAgent"
      host.esxcli.software.vib.install(:viburl => [qualified_vib_path])
    else # VirtualCenter
      host.esxcli.software.vib.install(:viburl => qualified_vib_path)
    end
  end

  # Esxcli wrapper method to remove a VIB represented by VIB name
  def remove_vib(vib_name)
    Puppet.debug("Attempting to remove the VIB: %s" % vib_name)
    # Note: This is odd, the ESX hostagent API can handle arrays, but the VirtualCenter API does not
    if vim.serviceInstance.content.about.apiType == "HostAgent"
      host.esxcli.software.vib.remove(:vibname => [vib_name])
    else # VirtualCenter
      host.esxcli.software.vib.remove(:vibname => vib_name)
    end
  end

  # Helper method to get list of mounted nfs shares
  def fetch_mounted_nfs_shares
    if resource[:nfs_hostname]
      # Get list of all mounted NFS datastores, and add it to mounted NFS shares
      Puppet.debug("Getting list of mounted NFS datastores...")
      host.esxcli.storage.nfs.list.each do |nfs_store|
        if nfs_store[:Host] && nfs_store[:Share] && nfs_store[:Mounted]
          key = nfs_store[:Host] + ":" + nfs_store[:Share]
          @mounted_nfs_shares[key] = { :volume_name => nfs_store[:VolumeName], :new_mount => false }
          Puppet.debug("Found existing NFS mount #{key} on the ESX host")
        end
      end
    end
  end

  # Helper method to mount a given NFS share on ESX as a specified volume_name
  def mount_nfs_share(share, volume_name)
    begin
      Puppet.debug("Mounting %s with volume name %s" % [share, volume_name])
      host.esxcli.storage.nfs.add({:host => resource[:nfs_hostname],
                                   :share => share,
                                   :volumename => volume_name})
      Puppet.debug("Mounted %s with volume name %s" % [share, volume_name])
      return true
    rescue => e
      log_error("Failed to mount", share, e)
    end
    false
  end

  # Helper method to unmount all NFS shares we mounted (not existing ones)
  def unmount_mounted_nfs_shares
    @mounted_nfs_shares.each do |key, value|
      if value[:new_mount]
        if unmount_nfs_share(value[:volume_name])
          @mounted_nfs_shares.delete(key) # Remove from mount map as well
        end
      end
    end
  end

  # Helper method to unmount a given NFS volume on ESX
  def unmount_nfs_share(volume_name)
    begin
      Puppet.debug("Unmounting volume name %s" % volume_name)
      host.esxcli.storage.nfs.remove({:volumename => volume_name})
      Puppet.debug("Unmounted volume name %s" % volume_name)
      return true
    rescue => e
      log_error("Failed to unmount", volume_name, e)
    end
    false
  end

end
