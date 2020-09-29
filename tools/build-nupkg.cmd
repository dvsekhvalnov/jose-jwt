nuget.exe update -self
cd ..\jose-jwt
dotnet restore jose-jwt.csproj
dotnet pack -c Release jose-jwt.csproj 