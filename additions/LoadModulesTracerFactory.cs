using NewRelic.Agent.Core.Tracer;

namespace NewRelic.Additions
{
	internal sealed class LoadModulesTracerFactory : ITracerFactory
	{
		public LoadModulesTracerFactory()
		{
			_initModulesTracerFactory = NewRelicUtility.GetTracerFactory("NewRelic.Agent.Core.Tracer.Factories.Web.InitModuleTracerFactory");
		}

		public ITracer GetTracer(Transaction transaction, ClassMethodSignature signature, object target, object[] arguments)
		{
			if (arguments.Length == 0 || _initModulesTracerFactory == null)
				return null;

			var result = _initModulesTracerFactory.GetTracer(transaction, signature, arguments[0], null);
			return result;
		}

		public bool BlameTracerGenerator
		{
			get { return _initModulesTracerFactory == null ? false : _initModulesTracerFactory.BlameTracerGenerator; }
		}

		public bool RequiresTransaction
		{
			get { return _initModulesTracerFactory == null ? false : _initModulesTracerFactory.RequiresTransaction; }
		}

		readonly ITracerFactory _initModulesTracerFactory;
	}
}
