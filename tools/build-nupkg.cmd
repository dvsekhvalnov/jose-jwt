nuget.exe update -self
cd ..\jose-jwt
dotnet restore
dotnet pack -c Release