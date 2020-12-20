from core import plugin, model

class _fuzzymatch(plugin._plugin):
    version = 0.2

    def install(self):
        # Register models
        model.registerModel("fuzzymatchString","_fuzzymatchString","_action","plugins.fuzzymatch.models.action")
        model.registerModel("fuzzymatchList","_fuzzymatchList","_action","plugins.fuzzymatch.models.action")
        model.registerModel("fuzzymatchLevenshteinDistance","_fuzzymatchLevenshteinDistance","_action","plugins.fuzzymatch.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("fuzzymatchString","_fuzzymatchString","_action","plugins.fuzzymatch.models.action")
        model.deregisterModel("fuzzymatchList","_fuzzymatchList","_action","plugins.fuzzymatch.models.action")
        model.deregisterModel("fuzzymatchLevenshteinDistance","_fuzzymatchLevenshteinDistance","_action","plugins.fuzzymatch.models.action")
        return True

    def upgrade(self,LatestPluginVersion):
        if self.version < 0.2:
            model.registerModel("fuzzymatchLevenshteinDistance","_fuzzymatchLevenshteinDistance","_action","plugins.fuzzymatch.models.action")
