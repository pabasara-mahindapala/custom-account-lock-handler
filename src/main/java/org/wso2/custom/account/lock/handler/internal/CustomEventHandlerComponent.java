package org.wso2.custom.account.lock.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.custom.account.lock.handler.CustomAccountLockHandler;

@Component(name = "org.wso2.custom.account.lock.handler",
        immediate = true)
public class CustomEventHandlerComponent {

    private static final Log log = LogFactory.getLog(CustomEventHandlerComponent.class);

    @Activate
    protected void activate(ComponentContext ctx) {
        try {
            CustomAccountServiceDataHolder.getInstance().setBundleContext(ctx.getBundleContext());
            CustomAccountLockHandler eventHandler = new CustomAccountLockHandler();
            ctx.getBundleContext().registerService(AbstractEventHandler.class.getName(), eventHandler, null);
            log.info("Custom event handler activated successfully.");
        } catch (Exception e) {
            log.error("Error while activating custom account lock handler bundle.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctx) {
        if (log.isDebugEnabled()) {
            log.debug("Custom event handler is deactivated");
        }
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        CustomAccountServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        CustomAccountServiceDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }
}