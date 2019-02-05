# encoding: utf-8
# frozen_string_literal: true

# copyright: 2015, Vulcano Security GmbH
# author: Dominik Richter
# author: Christoph Hartmann

require 'shellwords'

class SfWinFileResource < Inspec.resource(1) # :nodoc:
  name 'win_file'
  desc 'Use the `win_file` resource to test all system file types, including files, directories, symbolic links, named pipes, sockets, character devices, block devices, and doors.'
  example <<-EOH
    describe win_file('path') do
      it { should exist }
      it { should be_directory }
      it { should be_allowed('Synchronize', by_user: 'vagrant') }
      it { should be_allowed('ReadAndExecute', by: 'vagrant') }
    end
  EOH

  attr_reader :file, :mount_options
  def initialize(path)
    return skip_resource 'This resource only supports the Windows platform' unless inspec.os.windows?
    @file = inspec.backend.file(path)
  end

  %w(
    type exist? file? block_device? character_device? socket? directory?
    symlink? pipe? mode mode? owner owned_by? group grouped_into?
    link_path linked_to? mtime size selinux_label immutable?
    product_version file_version version? md5sum sha256sum
    path basename source source_path uid gid
  ).each do |m|
    define_method m.to_sym do |*args|
      file.method(m.to_sym).call(*args)
    end
  end

  def content
    res = file.content
    return nil if res.nil?
    res.force_encoding('utf-8')
  end

  def contain(*_)
    raise 'Contain is not supported. Please use standard RSpec matchers.'
  end

  def readable?(_by_usergroup, by_account)
    return false unless exist?

    file_permission_granted?('read', by_account)
  end

  def writable?(_by_usergroup, by_account)
    return false unless exist?

    file_permission_granted?('write', by_account)
  end

  def executable?(_by_usergroup, by_account)
    return false unless exist?

    file_permission_granted?('execute', by_account)
  end

  def allowed?(permission, opts = {})
    return false unless exist?

    file_permission_granted?(permission, opts[:by_user] || opts[:by])
  end

  def mounted?(expected_options = nil, identical = false)
    mounted = file.mounted

    # return if no additional parameters have been provided
    return file.mounted? if expected_options.nil?

    # deprecation warning, this functionality will be removed in future version
    warn "[DEPRECATION] `be_mounted.with and be_mounted.only_with` are deprecated.  Please use `mount('#{source_path}')` instead."

    # we cannot read mount data on non-Linux systems
    return nil unless inspec.os.linux?

    # parse content if we are on linux
    @mount_options ||= parse_mount_options(mounted.stdout, true)

    if identical
      # check if the options should be identical
      @mount_options == expected_options
    else
      # otherwise compare the selected values
      @mount_options.contains(expected_options)
    end
  end

  def suid
    (mode & 0o4000) > 0
  end

  alias setuid? suid

  def sgid
    (mode & 0o2000) > 0
  end

  alias setgid? sgid

  def sticky
    (mode & 0o1000) > 0
  end

  alias sticky? sticky

  def to_s
    if exist? && directory?
      "Directory #{source_path}"
    else
      "File #{source_path}"
    end
  end

  private

  def file_permission_granted?(access_type, by)
    raise 'Must provide a user for which to check the permissions' if by.nil? || by.empty?

    cmd = inspec.command("((Get-Acl '#{source_path}').access | Where-Object {$_.IdentityReference -like '*#{by}*'}).FileSystemRights")
    permissions = cmd.stdout.downcase.split(/\r\n/).join(', ')
    permissions_array = permissions.split(/, /).map(&:strip).reject { |p| p.nil? || p.empty? }

    # Cast as a boolean because inspec comparison
    !!permission_allows?(permissions_array, access_type)
  end

  def permission_allows?(arr, expected_perm)
    acceptable_perms = translate_perm_names(expected_perm).map(&:downcase)

    # Find the first instance and return it, which will be a string, which is
    # truthy. If none found, return nil which is falsey.
    arr.find { |actual_perm| acceptable_perms.include?(actual_perm.downcase) }
  end

  # Translates a developer-friendly string into a list of acceptable
  # FileSystemRights that match it, because Windows has a fun heirarchy of
  # permissions that are able to be noted in multiple ways.
  #
  # If checking for 'Modify', 'Read' won't cut it but 'FullControl' will. This
  # is because 'FullControl' contains the 'Modify' permission under it in the
  # heirarchy.
  #
  # This method translates that 'Modify' permission mentioned earlier to an
  # array of ['Modify', 'FullControl'], any of which indicates the user meets
  # the minimum clearance required by 'Modify'. As we get more granular, this
  # gets more complicated than just one level in the ACL heirarchy.
  #
  # See also: https://www.codeproject.com/Reference/871338/AccessControl-FileSystemRights-Permissions-Table
  def translate_perm_names(access_type)
    names = translate_common_perms(access_type)
    names ||= translate_granular_perms(access_type)
    names ||= translate_uncommon_perms(access_type)
    raise 'Invalid access_type provided' unless names

    names
  end

  def translate_common_perms(access_type)
    case access_type.downcase.gsub(/[_-]/, '')
    when 'fullcontrol'
      %w(FullControl)
    when 'modify'
      translate_perm_names('full-control') + %w(Modify)
    when 'read'
      translate_perm_names('modify') + %w(ReadAndExecute Read)
    when 'write'
      translate_perm_names('modify') + %w(Write)
    when 'execute'
      translate_perm_names('modify') + %w(ReadAndExecute ExecuteFile Traverse)
    when 'readandexecute'
      translate_perm_names('modify') + %w(ReadAndExecute)
    when 'delete'
      translate_perm_names('modify') + %w(Delete)
    end
  end

  def translate_uncommon_perms(access_type)
    case access_type.downcase.gsub(/[_-]/, '')
    when 'deletesubdirectoriesandfiles'
      translate_perm_names('full-control') + %w(DeleteSubdirectoriesAndFiles)
    when 'changepermissions'
      translate_perm_names('full-control') + %w(ChangePermissions)
    when 'takeownership'
      translate_perm_names('full-control') + %w(TakeOwnership)
    when 'synchronize'
      translate_perm_names('full-control') + %w(Synchronize)
    end
  end

  def translate_granular_perms(access_type)
    case access_type.downcase.gsub(/[_-]/, '')
    when 'writedata', 'createfiles'
      translate_perm_names('write') + %w(WriteData CreateFiles)
    when 'appenddata', 'createdirectories'
      translate_perm_names('write') + %w(CreateDirectories AppendData)
    when 'writeextendedattributes'
      translate_perm_names('write') + %w(WriteExtendedAttributes)
    when 'writeattributes'
      translate_perm_names('write') + %w(WriteAttributes)
    when 'readdata', 'listdirectory'
      translate_perm_names('read') + %w(ReadData ListDirectory)
    when 'readattributes'
      translate_perm_names('read') + %w(ReadAttributes)
    when 'readextendedattributes'
      translate_perm_names('read') + %w(ReadExtendedAttributes)
    when 'readpermissions'
      translate_perm_names('read') + %w(ReadPermissions)
    end
  end
end
