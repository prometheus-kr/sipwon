# 모든 하위 디렉토리에서 mvn spotless:apply 실행

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Root directory: $root"

# seqism 하위의 모든 pom.xml 찾기
$poms = Get-ChildItem -Path "$root" -Recurse -Filter pom.xml
Write-Host "Found $($poms.Count) pom.xml files in root directory."

foreach ($pom in $poms) {
    $dir = $pom.Directory.FullName
    Write-Host "Running mvn spotless:apply in $dir"
    Push-Location $dir
    mvn spotless:apply
    Pop-Location
}