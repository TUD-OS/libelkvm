#
# libelkvm - A library that allows execution of an ELF binary inside a virtual
# machine without a full-scale operating system
# Copyright (C) 2013-2015 Florian Pester <fpester@os.inf.tu-dresden.de>, Björn
# Döbel <doebel@os.inf.tu-dresden.de>,   economic rights: Technische Universitaet
# Dresden (Germany)
#
# This file is part of libelkvm.
#
# libelkvm is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# libelkvm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libelkvm.  If not, see <http://www.gnu.org/licenses/>.
#

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