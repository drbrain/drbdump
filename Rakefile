# -*- ruby -*-

require 'rubygems'
require 'hoe'

Hoe.plugin :minitest
Hoe.plugin :git

Hoe.spec 'drbdump' do
  developer 'Eric Hodel', 'drbrain@segment7.net'

  rdoc_locations << 'docs.seattlerb.org:/data/www/docs.seattlerb.org/drbdump/'

  self.readme_file = 'README.rdoc'
  self.licenses << 'MIT'

  self.extra_deps << ['capp', '~> 1.0']
  self.extra_deps << ['marshal-structure', '~> 1.0']
end

# vim: syntax=ruby
