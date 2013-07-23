# NewRelic Agent/Profiler for Mono

Directions (currently really ghetto because it's a proof of concept):

1. Install mono on the host system.
2. Clone https://github.com/LogosBible/mono.git, switch to the methodrewrite branch, and build/install it.
3. Uninstall the official mono package. (or make sure you don't use it)
4. Build and install xsp, which can be cloned from https://github.com/mono/xsp.git
5. Download either of the official .NET NewRelic agents and extract the contents. (you can get it on your Account Settings page)
6. Copy NewRelic.Agent.Core.dll into this directory.
7. Run additions/make.sh.
8. Run profiler/make.sh.
9. Merge the contents of instrumentation/CoreInstrumentation.Mono.xml into the CoreInstrumentation.xml that came with the NewRelic installer.
10. Copy `newrelic.xml` from the official agent into your web app's directory and rename it to `newrelic.config`. If you forget to rename the file, the NewRelic agent will crash with a `NullReferenceException` when trying to write to a nonexistent logger to warn you that you shouldn't have a file called `newrelic.xml`.
11. Do the things that I forgot to write down.
12. Run mono with the `--profile=newrelic` option. Make sure that the library built in step 8 is in your library path. `CoreInstrumentation.xml` should be in the working directory.
