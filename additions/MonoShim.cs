using System;
using System.Linq;
using NewRelic.Agent.Core;
using NewRelic.Agent.Core.Tracer;

// Compile with:
// mcs MonoShim.cs RunHooksTracerFactory.cs LoadModulesTracerFactory.cs NewRelicUtility.cs -target:library -r:System.Web,NewRelic.Agent.Core.dll -out:NewRelic.Additions.dll
// The NewRelic agent assembly will need to be in the current directory.

namespace NewRelic.Additions
{
	public static class MonoShim
	{
		static MonoShim()
		{
			var tracerService = NewRelic.Agent.Core.Agent.Instance.TracerService;
			if (tracerService == null || tracerService.TracerFactories == null)
				return;

			var factories = typeof(MonoShim).Assembly.GetTypes()
				.Where(type => typeof(ITracerFactory).IsAssignableFrom(type) && !type.IsAbstract)
				.Select(type => type.GetConstructor(Type.EmptyTypes))
				.Where(constructor => constructor != null)
				.Select(
					constructor =>
					{
						try
						{
							return constructor.Invoke(new object[0]);
						}
						catch (Exception)
						{
							return null;
						}
					})
				.OfType<ITracerFactory>()
				.ToList()
				.AsReadOnly();

			var tracerFactories = tracerService.TracerFactories;
			foreach (var factory in factories)
			{
				string factoryName = factory.GetType().FullName;
				tracerFactories.Add(factoryName, factory);
			}
		}

		public static void FinishTracer(object tracerObject, object returnValue, object exceptionObject)
		{
			AgentShim.FinishTracer(tracerObject, returnValue, exceptionObject);
		}

		public static object GetTracer(string tracerFactoryName, uint tracerArguments, string metricName, string assemblyName, string className, string methodName, string argumentSignature, object invocationTarget, object[] args)
		{
			return AgentShim.GetTracer(tracerFactoryName, tracerArguments, metricName, assemblyName, className, methodName, argumentSignature, invocationTarget, args);
		}
	}
}
