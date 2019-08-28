echo "Build nuget packages"


rm -Rf "P:\Dev\Gitlab\PH.PicoCrypt2\BuildPackages"

dotnet pack "P:\Dev\Gitlab\PH.PicoCrypt2\src\PH.PicoCrypt2\PH.PicoCrypt2\PH.PicoCrypt2.csproj" -c Release --include-symbols --include-source  -o "P:\Dev\Gitlab\PH.PicoCrypt2\BuildPackages"

nuget push  "P:\Dev\Gitlab\PH.PicoCrypt2\BuildPackages\PH.PicoCrypt2.*.nupkg" -Source "https://api.nuget.org/v3/index.json"

echo "done"