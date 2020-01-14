package com.identity.application.proviosioning;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.core.util.PermissionUpdateUtil;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.ProvisioningHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileAdmin;
import org.wso2.carbon.identity.user.profile.mgt.UserProfileException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class CustomProvisioningHandler implements ProvisioningHandler {

    private static final Log log = LogFactory.getLog(CustomProvisioningHandler.class);
    private static final String ALREADY_ASSOCIATED_MESSAGE = "UserAlreadyAssociated";
    private static volatile org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.impl.DefaultProvisioningHandler instance;
    private SecureRandom random = new SecureRandom();

    public static org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.impl.DefaultProvisioningHandler getInstance() {
        if (instance == null) {
            synchronized (org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.impl.DefaultProvisioningHandler.class) {
                if (instance == null) {
                    instance = new org.wso2.carbon.identity.application.authentication.framework.handler.provisioning.impl.DefaultProvisioningHandler();
                }
            }
        }
        return instance;
    }

    @Override
    public void handle(List<String> roles, String subject, Map<String, String> attributes,
                       String provisioningUserStoreId, String tenantDomain) throws FrameworkException {

        RegistryService registryService = FrameworkServiceComponent.getRegistryService();
        RealmService realmService = FrameworkServiceComponent.getRealmService();

        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            UserRealm realm = AnonymousSessionUtil.getRealmByTenantDomain(registryService,
                    realmService, tenantDomain);

            String username = MultitenantUtils.getTenantAwareUsername(subject);

            String userStoreDomain;
            UserStoreManager userStoreManager;
            if (IdentityConstants.AS_IN_USERNAME_USERSTORE_FOR_JIT
                    .equalsIgnoreCase(provisioningUserStoreId)) {
                String userStoreDomainFromSubject = UserCoreUtil.extractDomainFromName(subject);
                try {
                    userStoreManager = getUserStoreManager(realm, userStoreDomainFromSubject);
                    userStoreDomain = userStoreDomainFromSubject;
                } catch (FrameworkException e) {
                    log.error("User store domain " + userStoreDomainFromSubject + " does not exist for the tenant "
                            + tenantDomain + ", hence provisioning user to "
                            + UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME);
                    userStoreDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
                    userStoreManager = getUserStoreManager(realm, userStoreDomain);
                }
            } else {
                userStoreDomain = getUserStoreDomain(provisioningUserStoreId, realm);
                userStoreManager = getUserStoreManager(realm, userStoreDomain);
            }
            username = UserCoreUtil.removeDomainFromName(username);

            if (log.isDebugEnabled()) {
                log.debug("User: " + username + " with roles : " + roles + " is going to be provisioned");
            }

            // If internal roles exists convert internal role domain names to pre defined camel case domain names.
            List<String> rolesToAdd = convertInternalRoleDomainsToCamelCase(roles);

            // addingRoles = rolesToAdd AND allExistingRoles
            Collection<String> addingRoles = getRolesAvailableToAdd(userStoreManager, rolesToAdd);

            String idp = attributes.remove(IdentityConstants.IDP_ID);
            String subjectVal = attributes.remove(IdentityConstants.ASSOCIATED_ID);

            Map<String, String> userClaims = prepareClaimMappings(attributes);

            if (userStoreManager.isExistingUser(username)) {

                if (roles != null && !roles.isEmpty()) {
                    // Update user
                    List<String> currentRolesList = Arrays.asList(userStoreManager
                            .getRoleListOfUser(username));
                    // addingRoles = (newRoles AND existingRoles) - currentRolesList)
                    addingRoles.removeAll(currentRolesList);

                    Collection<String> deletingRoles = retrieveRolesToBeDeleted(realm, currentRolesList, rolesToAdd);

                    // TODO : Does it need to check this?
                    // Check for case whether superadmin login
                    handleFederatedUserNameEqualsToSuperAdminUserName(realm, username, userStoreManager, deletingRoles);

                    updateUserWithNewRoleSet(username, userStoreManager, rolesToAdd, addingRoles, deletingRoles);
                }

                if (!userClaims.isEmpty()) {
                    userClaims.remove(IdentityConstants.PASSWORD);
                    userStoreManager.setUserClaimValues(UserCoreUtil.removeDomainFromName(username), userClaims, null);
                }

                UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();

                if (StringUtils.isEmpty(userProfileAdmin.getNameAssociatedWith(idp, subjectVal))) {
                    // Associate User
                    associateUser(username, userStoreDomain, tenantDomain, subjectVal, idp);
                }
            } else {
                String password = generatePassword();
                String passwordFromUser = userClaims.get(IdentityConstants.PASSWORD);
                if (StringUtils.isNotEmpty(passwordFromUser)) {
                    password = passwordFromUser;
                }
                userClaims.remove(IdentityConstants.PASSWORD);
                userStoreManager
                        .addUser(username, password, addingRoles.toArray(new String[addingRoles.size()]), userClaims,
                                null);
                // Associate User
                associateUser(username, userStoreDomain, tenantDomain, subjectVal, idp);

                if (log.isDebugEnabled()) {
                    log.debug("Federated user: " + username
                            + " is provisioned by authentication framework with roles : "
                            + Arrays.toString(addingRoles.toArray(new String[addingRoles.size()])));
                }
            }

            PermissionUpdateUtil.updatePermissionTree(tenantId);

        } catch (org.wso2.carbon.user.api.UserStoreException | CarbonException | UserProfileException e) {
            throw new FrameworkException("Error while provisioning user : " + subject, e);
        } finally {
            IdentityUtil.clearIdentityErrorMsg();
        }
    }

    protected void associateUser(String username, String userStoreDomain, String tenantDomain, String subject,
                                 String idp) throws FrameworkException {

        String usernameWithUserstoreDomain = UserCoreUtil.addDomainToName(username, userStoreDomain);
        try {
            // start tenant flow
            FrameworkUtils.startTenantFlow(tenantDomain);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(usernameWithUserstoreDomain);

            if (!StringUtils.isEmpty(idp) && !StringUtils.isEmpty(subject)) {
                UserProfileAdmin userProfileAdmin = UserProfileAdmin.getInstance();
                userProfileAdmin.associateID(idp, subject);

                if (log.isDebugEnabled()) {
                    log.debug("Associated local user: " + usernameWithUserstoreDomain + " in tenant: " +
                            tenantDomain + " to the federated subject : " + subject + " in IdP: " + idp);
                }
            } else {
                throw new FrameworkException("Error while associating local user: " + usernameWithUserstoreDomain +
                        " in tenant: " + tenantDomain + " to the federated subject : " + subject + " in IdP: " + idp);
            }
        } catch (UserProfileException e) {
            if (isUserAlreadyAssociated(e)) {
                log.info("An association already exists for user: " + subject + ". Skip association while JIT " +
                        "provisioning");
            } else {
                throw new FrameworkException("Error while associating local user: " + usernameWithUserstoreDomain +
                        " in tenant: " + tenantDomain + " to the federated subject : " + subject + " in IdP: " + idp, e);
            }
        } finally {
            // end tenant flow
            FrameworkUtils.endTenantFlow();
        }
    }

    private boolean isUserAlreadyAssociated(UserProfileException e) {
        return e.getMessage() != null && e.getMessage().contains(ALREADY_ASSOCIATED_MESSAGE);
    }

    private void updateUserWithNewRoleSet(String username, UserStoreManager userStoreManager, List<String> rolesToAdd,
                                          Collection<String> addingRoles, Collection<String> deletingRoles)
            throws UserStoreException {
        if (log.isDebugEnabled()) {
            log.debug("Deleting roles : "
                    + Arrays.toString(deletingRoles.toArray(new String[deletingRoles.size()]))
                    + " and Adding roles : "
                    + Arrays.toString(addingRoles.toArray(new String[addingRoles.size()])));
        }
        userStoreManager.updateRoleListOfUser(username, deletingRoles.toArray(new String[deletingRoles
                        .size()]),
                addingRoles.toArray(new String[addingRoles.size()]));
        if (log.isDebugEnabled()) {
            log.debug("Federated user: " + username
                    + " is updated by authentication framework with roles : "
                    + rolesToAdd);
        }
    }

    private void handleFederatedUserNameEqualsToSuperAdminUserName(UserRealm realm, String username,
                                                                   UserStoreManager userStoreManager,
                                                                   Collection<String> deletingRoles)
            throws UserStoreException, FrameworkException {
        if (userStoreManager.getRealmConfiguration().isPrimary()
                && username.equals(realm.getRealmConfiguration().getAdminUserName())) {
            if (log.isDebugEnabled()) {
                log.debug("Federated user's username is equal to super admin's username of local IdP.");
            }

            // Whether superadmin login without superadmin role is permitted
            if (deletingRoles
                    .contains(realm.getRealmConfiguration().getAdminRoleName())) {
                if (log.isDebugEnabled()) {
                    log.debug("Federated user doesn't have super admin role. Unable to sync roles, since" +
                            " super admin role cannot be unassigned from super admin user");
                }
                throw new FrameworkException(
                        "Federated user which having same username to super admin username of local IdP," +
                                " trying login without having super admin role assigned");
            }
        }
    }

    private Map<String, String> prepareClaimMappings(Map<String, String> attributes) {
        Map<String, String> userClaims = new HashMap<>();
        if (attributes != null && !attributes.isEmpty()) {
            for (Map.Entry<String, String> entry : attributes.entrySet()) {
                String claimURI = entry.getKey();
                String claimValue = entry.getValue();
                if (!(StringUtils.isEmpty(claimURI) || StringUtils.isEmpty(claimValue))) {
                    userClaims.put(claimURI, claimValue);
                }
            }
        }
        return userClaims;
    }

    private Collection<String> getRolesAvailableToAdd(UserStoreManager userStoreManager, List<String> roles)
            throws UserStoreException {

        List<String> rolesAvailableToAdd = new ArrayList<>();
        rolesAvailableToAdd.addAll(roles);

        String[] roleNames = userStoreManager.getRoleNames();
        if (roleNames != null) {
            rolesAvailableToAdd.retainAll(Arrays.asList(roleNames));
        }
        return rolesAvailableToAdd;
    }

    private UserStoreManager getUserStoreManager(UserRealm realm, String userStoreDomain)
            throws UserStoreException, FrameworkException {
        UserStoreManager userStoreManager;
        if (userStoreDomain != null && !userStoreDomain.isEmpty()) {
            userStoreManager = realm.getUserStoreManager().getSecondaryUserStoreManager(
                    userStoreDomain);
        } else {
            userStoreManager = realm.getUserStoreManager();
        }

        if (userStoreManager == null) {
            throw new FrameworkException("Specified user store is invalid");
        }
        return userStoreManager;
    }

    /**
     * Compute the user store which user to be provisioned
     *
     * @return
     * @throws UserStoreException
     */
    private String getUserStoreDomain(String userStoreDomain, UserRealm realm)
            throws FrameworkException, UserStoreException {

        // If the any of above value is invalid, keep it empty to use primary userstore
        if (userStoreDomain != null
                && realm.getUserStoreManager().getSecondaryUserStoreManager(userStoreDomain) == null) {
            throw new FrameworkException("Specified user store domain " + userStoreDomain
                    + " is not valid.");
        }

        return userStoreDomain;
    }

    /**
     * remove user store domain from names except the domain 'Internal'
     *
     * @param names
     * @return
     */
    private List<String> removeDomainFromNamesExcludeInternal(List<String> names, int tenantId) {
        List<String> nameList = new ArrayList<String>();
        for (String name : names) {
            String userStoreDomain = IdentityUtil.extractDomainFromName(name);
            if (UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(userStoreDomain)) {
                nameList.add(name);
            } else {
                nameList.add(UserCoreUtil.removeDomainFromName(name));
            }
        }
        return nameList;
    }

    /**
     * Check for internal roles and convert internal role domain names to camel case to match with predefined
     * internal role domains.
     *
     * @param roles roles to verify and update
     * @return updated role list
     */
    private List<String> convertInternalRoleDomainsToCamelCase(List<String> roles) {

        List<String> updatedRoles = new ArrayList<>();

        if (roles != null) {
            // If internal roles exist, convert internal role domain names to case sensitive predefined domain names.
            for (String role : roles) {
                if (StringUtils.containsIgnoreCase(role, UserCoreConstants.INTERNAL_DOMAIN + CarbonConstants
                        .DOMAIN_SEPARATOR)) {
                    updatedRoles.add(UserCoreConstants.INTERNAL_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR +
                            UserCoreUtil.removeDomainFromName(role));
                } else if (StringUtils.containsIgnoreCase(role, IdentityConstants.APPLICATION_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR)) {
                    updatedRoles.add(IdentityConstants.APPLICATION_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR + UserCoreUtil
                            .removeDomainFromName(role));
                } else if (StringUtils.containsIgnoreCase(role, IdentityConstants.WORKFLOW_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR)) {
                    updatedRoles.add(IdentityConstants.WORKFLOW_DOMAIN + CarbonConstants.DOMAIN_SEPARATOR + UserCoreUtil
                            .removeDomainFromName(role));
                } else {
                    updatedRoles.add(role);
                }
            }
        }

        return updatedRoles;
    }

    /**
     * Retrieve the list of roles to be deleted.
     *
     * @param realm            user realm
     * @param currentRolesList current role list of the user
     * @param rolesToAdd       roles that are about to be added
     * @return roles to be deleted
     * @throws UserStoreException When failed to access user store configuration
     */
    protected List<String> retrieveRolesToBeDeleted(UserRealm realm, List<String> currentRolesList,
                                                    List<String> rolesToAdd) throws UserStoreException {

        List<String> deletingRoles = new ArrayList<String>();
        deletingRoles.addAll(currentRolesList);

        // deletingRoles = currentRolesList - rolesToAdd
        deletingRoles.removeAll(rolesToAdd);

        // Exclude Internal/everyonerole from deleting role since its cannot be deleted
        deletingRoles.remove(realm.getRealmConfiguration().getEveryOneRoleName());

        return deletingRoles;
    }

    /**
     * Generates (random) password for user to be provisioned
     *
     * @return
     */
    private String generatePassword() {
        //generate password alighn with regex pattern
        return RandomStringUtils.randomNumeric(12);
    }

}

