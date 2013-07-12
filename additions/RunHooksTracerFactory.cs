using System;
using System.Reflection;
using System.Web;
using NewRelic.Agent.Core.Tracer;

namespace NewRelic.Additions
{
	internal sealed class RunHooksTracerFactory : ITracerFactory
	{
		public RunHooksTracerFactory()
		{
			_executionPipelineStepTracerFactory = NewRelicUtility.GetTracerFactory("NewRelic.Agent.Core.Tracer.Factories.Web.ExecutionPipelineStepTracerFactory");

			_iteratorType = typeof(HttpApplication).Assembly.GetType("System.Web.HttpApplication+<RunHooks>c__Iterator2");
			if (_iteratorType != null)
			{
				_delegateField = _iteratorType.GetField("list", BindingFlags.NonPublic | BindingFlags.Instance);
				_parentField = _iteratorType.GetField("$this", BindingFlags.NonPublic | BindingFlags.Instance);
			}
		}

		public ITracer GetTracer(Transaction transaction, ClassMethodSignature signature, object target, object[] arguments)
		{
			Console.Error.WriteLine("other tracer!");
			if (_executionPipelineStepTracerFactory == null || _delegateField == null || _parentField == null ||
				!_iteratorType.IsInstanceOfType(target))
			{
				return null;
			}
			Console.Error.WriteLine("continuing '{0}' '{1}'", transaction, transaction == null ? null : transaction.LastTracer);
			return _executionPipelineStepTracerFactory.GetTracer(transaction, signature, _parentField.GetValue(target),
				new object[] { new ExecutionStepShim { Handler = _delegateField.GetValue(target) } });
		}

		public bool BlameTracerGenerator
		{
			get { return _executionPipelineStepTracerFactory == null ? false : _executionPipelineStepTracerFactory.BlameTracerGenerator; }
		}

		public bool RequiresTransaction
		{
			get { return _executionPipelineStepTracerFactory == null ? false : _executionPipelineStepTracerFactory.RequiresTransaction; }
		}

		private sealed class ExecutionStepShim
		{
			public object Handler { get; set; }
		}

		readonly Type _iteratorType;
		readonly FieldInfo _delegateField;
		readonly FieldInfo _parentField;
		readonly ITracerFactory _executionPipelineStepTracerFactory;
	}
}