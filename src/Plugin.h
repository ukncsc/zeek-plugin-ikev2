
#ifndef BRO_PLUGIN_IKE_IKEV2
#define BRO_PLUGIN_IKE_IKEV2

#include <plugin/Plugin.h>

namespace plugin {
namespace Zeek_IKEv2 {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
