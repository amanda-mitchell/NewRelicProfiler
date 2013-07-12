#!/bin/sh

mcs MonoShim.cs RunHooksTracerFactory.cs LoadModulesTracerFactory.cs NewRelicUtility.cs -target:library -r:System.Web,NewRelic.Agent.Core.dll -out:NewRelic.Additions.dll -lib:..

