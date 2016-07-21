Pod::Spec.new do |spec|
  spec.name = "TplgyTGL"
  spec.version = "0.1.0"
  spec.summary = 'Topology TGL for iOS'
  spec.author = { 'Topology LP' => 'dev@topologyinc.com' }
  spec.homepage = 'http://www.topologyinc.com'
  spec.license = 'LGPL'
  spec.platform = :ios, '8.0'
  spec.vendored_frameworks = 'TplgyTGL.framework'
  spec.library = 'c++'
  spec.frameworks = 'Foundation', 'Security', 'SystemConfiguration'
end
