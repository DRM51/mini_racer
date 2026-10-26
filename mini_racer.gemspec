# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "mini_racer/version"

Gem::Specification.new do |spec|
  spec.name = "drm51_mini_racer"
  spec.version = MiniRacer::VERSION
  spec.authors = ["Sam Saffron"]
  spec.email = ["sam.saffron@gmail.com"]

  spec.summary = "DRM51 build of mini_racer: embedded V8 for Ruby"
  spec.description =
    "DRM51's fork of mini_racer (based on mini_racer 0.22.2), on V8 " \
      "#{MiniRacer::VERSION.split(".").first(4).join(".")}. Not an upstream " \
      "mini_racer release; versions follow the V8 version."
  spec.homepage = "https://github.com/DRM51/mini_racer"
  spec.license = "MIT"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/DRM51/mini_racer/issues",
    "changelog_uri" =>
      "https://github.com/DRM51/mini_racer/blob/v#{spec.version}/CHANGELOG",
    "source_code_uri" =>
      "https://github.com/DRM51/mini_racer/tree/v#{spec.version}"
  }

  spec.files =
    Dir[
      "lib/**/*.rb",
      "ext/**/*",
      "README.md",
      "LICENSE.txt",
      "CHANGELOG",
      "CODE_OF_CONDUCT.md"
    ]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake", ">= 12.3.3"
  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake-compiler"
  spec.add_development_dependency "activesupport", "> 6"
  spec.add_development_dependency "m"
  spec.add_development_dependency "rubocop"
  spec.add_development_dependency "syntax_tree"

  spec.add_dependency "drm51_libv8_node", MiniRacer::LIBV8_NODE_VERSION
  spec.require_paths = %w[lib ext]

  spec.extensions = %w[
    ext/mini_racer_loader/extconf.rb
    ext/mini_racer_extension/extconf.rb
  ]

  spec.required_ruby_version = ">= 3.3"
end
