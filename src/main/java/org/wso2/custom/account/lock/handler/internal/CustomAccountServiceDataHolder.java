package org.wso2.custom.account.lock.handler.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

public class CustomAccountServiceDataHolder {

    private static volatile CustomAccountServiceDataHolder customAccountServiceDataHolder = new CustomAccountServiceDataHolder();

    private BundleContext bundleContext;
    private IdentityGovernanceService identityGovernanceService;

    private CustomAccountServiceDataHolder() {

    }

    public static CustomAccountServiceDataHolder getInstance() {
        return customAccountServiceDataHolder;
    }

    public BundleContext getBundleContext() {
        return bundleContext;
    }

    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    public IdentityGovernanceService getIdentityGovernanceService() {
        return identityGovernanceService;
    }

    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {
        this.identityGovernanceService = identityGovernanceService;
    }
}
