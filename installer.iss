[Setup]
AllowNoIcons=yes
AppName=Textractor
ArchitecturesAllowed=x86 x64
AppVersion={#VERSION}
CloseApplications=no
DefaultDirName={userdesktop}\Textractor
DirExistsWarning=no
DefaultGroupName=Textractor
MinVersion=6.1
OutputBaseFilename=Textractor-{#VERSION}-Setup
OutputDir=Builds
PrivilegesRequired=lowest
SolidCompression=yes
Uninstallable=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "tu"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "sc"; MessagesFile: "compiler:Languages\Unofficial\ChineseSimplified.isl"
Name: "id"; MessagesFile: "compiler:Languages\Unofficial\Indonesian.isl"
Name: "pt"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "th"; MessagesFile: "compiler:Languages\Unofficial\Thai.isl"


[Files]
Source: "Builds\Runtime\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor--{#VERSION}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor-Spanish-{#VERSION}\*"; DestDir: "{app}"; Languages: es; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor-Russian-{#VERSION}\*"; DestDir: "{app}"; Languages: ru; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor-Turkish-{#VERSION}\*"; DestDir: "{app}"; Languages: tu; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor-Simplified-Chinese-{#VERSION}\*"; DestDir: "{app}"; Languages: sc; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor-Indonesian-{#VERSION}\*"; DestDir: "{app}"; Languages: id; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor-Portuguese-{#VERSION}\*"; DestDir: "{app}"; Languages: pt; Flags: recursesubdirs ignoreversion
Source: "Builds\Textractor-Thai-{#VERSION}\*"; DestDir: "{app}"; Languages: th; Flags: recursesubdirs ignoreversion
