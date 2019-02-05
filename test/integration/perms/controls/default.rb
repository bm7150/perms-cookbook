# encoding: utf-8

describe win_file('C:\TestDir') do
  it { should exist }
  it { should be_directory }
  it { should be_allowed('Synchronize', by_user: 'vagrant') }
  it { should be_allowed('ReadAndExecute', by_user: 'vagrant') }
  it { should be_allowed('Write', by_user: 'vagrant') }
end

describe win_file('C:\TestDir\TestFile.txt') do
  it { should exist }
  it { should be_allowed('Synchronize', by_user: 'vagrant') }
  it { should be_allowed('ReadAndExecute', by_user: 'vagrant') }
  it { should be_allowed('Write', by_user: 'vagrant') }
end
