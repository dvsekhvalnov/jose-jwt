tools\nuget.exe update -self

if not exist JWT\bin\Release\nupkg mkdir JWT\bin\Release\nupkg
if not exist JWT\bin\Release\nupkg\content mkdir JWT\bin\Release\nupkg\content
if not exist JWT\bin\Release\nupkg\lib\4.0 mkdir JWT\bin\Release\nupkg\lib\4.0

copy JWT\bin\Release\jose-jwt.dll JWT\bin\Release\nupkg\lib\4.0\
copy LICENSE JWT\bin\Release\nupkg\content

tools\nuget.exe pack jose-jwt.nuspec -BasePath JWT\bin\Release\nupkg