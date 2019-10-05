# ManagedSandbox
A managed sandbox implementation that lets developers choose between various levels of security.

NOTE: This code is intended to lay the foundation for creating a secure sandbox, but by default is not fully locked down.

The following resources were used to write this code:

|Resource|Usage|
|-|-|
|[MalwareTech](https://github.com/MalwareTech/AppContainerSandbox)|Launching a process in an AppContainer|
|[pinvoke.net](https://pinvoke.net/)|Various interop stubs|
|[Practical Sandboxing 1](http://blogs.msdn.com/b/david_leblanc/archive/2007/07/27/practical-windows-sandboxing-part-1.aspx) [2](http://blogs.msdn.com/b/david_leblanc/archive/2007/07/30/practical-windows-sandboxing-part-2.aspx) [3](http://blogs.msdn.com/b/david_leblanc/archive/2007/07/31/practical-windows-sandboxing-part-3.aspx)|Various sandboxing concepts|

## Usage
An application is launched in a sandbox using the `SandboxedProcess` class, and specifying the various `IProtection` implementations applicable for the sandboxing scenario.

```
var sandboxProcess = SandboxedProcess.Start(
    @"c:\foo.exe",
    new JobObjectProtection(),
    new DesktopProtection(),
    new RestrictedTokenProtection(),
    new AppContainerProtection());
```

## Protections
### AppContainer
### Desktop
### JobObject
### Restricted Token

## Troubleshooting
