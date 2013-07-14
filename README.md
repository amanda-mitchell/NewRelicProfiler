# NewRelic Agent/Profiler for Mono

Directions (currently really ghetto because it's a proof of concept):

1. Install mono on the host system.
2. Clone https://github.com/LogosBible/mono.git, switch to the methodrewrite branch, and build/install it.
3. Uninstall the official mono package.
4. Build and install xsp, which can be cloned from https://github.com/mono/xsp.git
5. Download either of the official .NET NewRelic agents and extract the contents. (you can get it on your Account Settings page)
6. Copy NewRelic.Agent.Core.dll into this directory.
7. Run additions/make.sh.
8. Run profiler/make.sh.
