
#include "Plugin.h"
#include "IKEv2.h"

namespace plugin { namespace Zeek_IKEv2 { Plugin plugin; } }

using namespace plugin::Zeek_IKEv2;

plugin::Configuration Plugin::Configure()
	{
	AddComponent(new ::analyzer::Component("IKEv2",
				::analyzer::IKEv2::IKEv2_Analyzer::InstantiateAnalyzer));
	
	plugin::Configuration config;
	config.name = "Zeek::IKEv2";
	config.description = "Protocol analyser for IKEv2 initial messages";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
	}
