#
# Cookbook:: perms-cookbook
# Recipe:: default
#

directory 'C:\TestDir' do
  inherits true
  rights WINDOWS_PERM.fetch(:synchronize), node['perms_cookbook']['user'], applies_to_children: true
  rights WINDOWS_PERM.fetch(:read_and_execute), node['perms_cookbook']['user'], applies_to_children: true
  rights WINDOWS_PERM.fetch(:write), node['perms_cookbook']['user'], applies_to_children: true
end

cookbook_file 'files/default/TestFile.txt' do
  path 'C:\TestDir\TestFile.txt'
end
