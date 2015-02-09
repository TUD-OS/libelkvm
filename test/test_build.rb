
def build(cc, cxx)
  `CC=#{cc} CXX=#{cxx} cmake ../.. 2>&1`
  `sudo make -C include install 2>&1`
  puts "Building with #{cc}"
  output = `make -j5 2>&1`
  if !$?.success?
    puts "Build failed with #{$?}"
    puts "Build with #{cc} failed, here is some output:"
    puts output
  else
    puts "Build successfull"
  end
  $?.success?
end

build_dir = ".build"
Dir.mkdir(build_dir)
Dir.chdir(build_dir)

working_build = true
working_build = build("gcc", "g++")
working_build = build("clang", "clang++") if working_build

Dir.chdir("..")
`rm -rf #{build_dir}`
exit working_build
