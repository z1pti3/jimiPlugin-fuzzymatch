from core import plugin, model

class _virustotal(plugin._plugin):
    version = 0.1

    def install(self):
        # Register models
        model.registerModel("virustotalIPDetails","_virustotalIPDetails","_action","plugins.virustotal.models.action")
        model.registerModel("virustotalDomainDetails","_virustotalDomainDetails","_action","plugins.virustotal.models.action")
        model.registerModel("virustotalFileDetails","_virustotalFileDetails","_action","plugins.virustotal.models.action")
        model.registerModel("virustotalFileBehaviour","_virustotalFileBehaviour","_action","plugins.virustotal.models.action")
        model.registerModel("virustotalFileSubmission","_virustotalFileSubmission","_action","plugins.virustotal.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("virustotalIPDetails","_virustotalIPDetails","_action","plugins.virustotal.models.action")
        model.deregisterModel("virustotalDomainDetails","_virustotalDomainDetails","_action","plugins.virustotal.models.action")
        model.deregisterModel("virustotalFileDetails","_virustotalFileDetails","_action","plugins.virustotal.models.action")
        model.deregisterModel("virustotalFileBehaviour","_virustotalFileBehaviour","_action","plugins.virustotal.models.action")
        model.deregisterModel("virustotalFileSubmission","_virustotalFileSubmission","_action","plugins.virustotal.models.action")
        return True

    def upgrade(self,LatestPluginVersion):
        pass
        #if self.version < 0.2:
