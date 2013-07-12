using NewRelic.Agent.Core.Tracer;

namespace NewRelic.Additions
{
	internal static class NewRelicUtility
	{
		public static ITracerFactory GetTracerFactory(string name)
		{
			var tracerService = NewRelic.Agent.Core.Agent.Instance.TracerService;
			if (tracerService == null || tracerService.TracerFactories == null)
				return null;

			return tracerService.TracerFactories[name];
		}
	}
}