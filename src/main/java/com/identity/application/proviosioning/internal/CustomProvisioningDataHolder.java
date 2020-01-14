package com.identity.application.proviosioning.internal;


import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

public class CustomProvisioningDataHolder {

    private static RealmService realmService;
    private static RegistryService registryService;

    public static RealmService getRealmService() {
        return CustomProvisioningDataHolder.realmService;
    }

    public static void setRealmService(RealmService realmService) {
        CustomProvisioningDataHolder.realmService = realmService;
    }

    public static void setRegistryService(RegistryService registryService) {
        CustomProvisioningDataHolder.registryService = registryService;
    }

    public static RegistryService getRegistryService() {
        return CustomProvisioningDataHolder.registryService;
    }

}
