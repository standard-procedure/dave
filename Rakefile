desc "Run specs for all gems"
task :spec do
  %w[dave-server dave-filesystem dave-security].each do |gem_dir|
    sh({ "BUNDLE_GEMFILE" => File.expand_path("#{gem_dir}/Gemfile") },
       "bundle exec rspec", chdir: gem_dir)
  end
end

task default: :spec
