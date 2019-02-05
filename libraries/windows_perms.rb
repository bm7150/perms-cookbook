# @see https://www.codeproject.com/Reference/871338/AccessControl-FileSystemRights-Permissions-Table
# @see https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=netframework-4.7.1
# Gathered from Server2016 and confirmed on Server2008r2

WINDOWS_PERM = {
  append_data:                      0b000000000000000000100,
  change_permissions:               0b001000000000000000000,
  create_directories:               0b000000000000000000100,
  create_files:                     0b000000000000000000010,
  delete:                           0b000001000000000000000,
  delete_subdirectories_and_files:  0b000000000000001000000,
  execute_file:                     0b000000000000000100000,
  full_control:                     0b111110000000111111111,
  list_directory:                   0b000000000000000000001,
  modify:                           0b000110000000110111111,
  read:                             0b000100000000010001001,
  read_and_execute:                 0b000100000000010101001,
  read_attributes:                  0b000000000000010000000,
  read_data:                        0b000000000000000000001,
  read_extended_attributes:         0b000000000000000001000,
  read_permissions:                 0b000100000000000000000,
  synchronize:                      0b100000000000000000000,
  take_ownership:                   0b010000000000000000000,
  traverse:                         0b000000000000000100000,
  write:                            0b000000000000100010110,
  write_attributes:                 0b000000000000100000000,
  write_data:                       0b000000000000000000010,
  write_extended_attributes:        0b000000000000000010000,
}.freeze unless defined? WINDOWS_PERM
