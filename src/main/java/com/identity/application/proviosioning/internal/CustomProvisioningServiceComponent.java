package com.identity.application.proviosioning.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;

import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="com.cbre.custom.provisioning.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class CustomProvisioningServiceComponent {

    private static Log log = LogFactory.getLog(CustomProvisioningServiceComponent.class);

    protected void activate(ComponentContext ctxt) {
        try {
            log.info("CustomProvisioningServiceComponent bundle is activated");
        } catch (Throwable e) {
            log.error("CustomProvisioningServiceComponent bundle activation Failed", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("CustomProvisioningServiceComponent bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        CustomProvisioningDataHolder.setRealmService(null);
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        CustomProvisioningDataHolder.setRealmService(realmService);
    }

    protected void unsetRegistryService(RegistryService registryService) {
        log.debug("UnSetting the Registry Service");
        CustomProvisioningDataHolder.setRegistryService(null);
    }

    protected void setRegistryService(RegistryService registryService) {
        log.debug("Setting the Registry Service");
        CustomProvisioningDataHolder.setRegistryService(registryService);
    }



}