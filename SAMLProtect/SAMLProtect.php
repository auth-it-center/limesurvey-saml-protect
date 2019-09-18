<?php

/**
 * LimeSurvey SAML protected Surveys
 *
 * This plugin forces selected surveys to
 * be displayed/submitted only to/by SAML users
 *
 * Author: Panagiotis Karatakis <karatakis@it.auth.gr>
 * Licence: GPL3
 *
 * Sources:
 * https://manual.limesurvey.org/Plugins_-_advanced
 * https://manual.limesurvey.org/Plugin_events
 * https://medium.com/@evently/creating-limesurvey-plugins-adcdf8d7e334
 */

class SAMLProtect extends Limesurvey\PluginManager\PluginBase
{
    protected $storage = 'DbStorage';
    static protected $description = 'This plugin forces selected surveys to be protected by SAML';
    static protected $name = 'SAMLProtect';

    protected $settings = [];

    public function init()
    {
        $this->subscribe('beforeSurveySettings');
        $this->subscribe('newSurveySettings');
        $this->subscribe('beforeSurveyPage');
        $this->subscribe('getGlobalBasePermissions');
    }

    public function beforeSurveySettings()
    {
        $permission = Permission::model()->hasGlobalPermission('plugin_settings', 'update');
        if ($permission) {
            $event = $this->event;
            $event->set('surveysettings.' . $this->id, [
                'name' => get_class($this),
                'settings' => [
                    'auth_protection_enabled' => [
                        'type' => 'checkbox',
                        'label' => 'SAML Guard',
                        'help' => 'Only SAML users should see the survey ?',
                        'default' => false,
                        'current' => $this->get('auth_protection_enabled', 'Survey', $event->get('survey'), false),
                    ],
                    'auth_admin_protection_enabled' => [
                        'type' => 'checkbox',
                        'label' => 'Admin Guard',
                        'help' => 'Only Admin users should see the survey ?',
                        'default' => false,
                        'current' => $this->get('auth_admin_protection_enabled', 'Survey', $event->get('survey'), false),
                    ],
                    'guard_bypass' => [
                        'type' => 'checkbox',
                        'label' => 'Guard Bypass',
                        'help' => 'Only Admin users can bypass other plugin guards',
                        'default' => false,
                        'current' => $this->get('guard_bypass', 'Survey', $event->get('survey'), false),
                    ]
                ]
            ]);
        }
    }

    public function newSurveySettings()
    {
        $event = $this->event;
        foreach ($event->get('settings') as $name => $value)
        {
            $default = $event->get($name, null, null, isset($this->settings[$name]['default']));
            $this->set($name, $value, 'Survey', $event->get('survey'), $default);
        }
    }

    public function beforeSurveyPage()
    {
        $event = $this->event;
        $surveyId = $event->get('surveyId');
        $this->SAMLGuard($surveyId);
        $this->adminGuard($surveyId);
    }

    public function SAMLGuard($surveyId)
    {
        $flag = $this->get('auth_protection_enabled', 'Survey', $surveyId, false);
        if ($flag) {
            // Authenticate user
            $AuthSAML = $this->pluginManager->loadPlugin('AuthSAML');
            $ssp = $AuthSAML->get_saml_instance();
            $ssp->requireAuth();
        }
    }

    public function adminGuard($surveyId)
    {
        $flag = $this->get('auth_admin_protection_enabled', 'Survey', $surveyId, false);
        if ($flag) {
            $isAdmin = $this->isAdminUser();
            if (!$isAdmin) {
                throw new CHttpException(401, gT("We are sorry but you do not have permissions to do this."));
            }
        }
        return false;
    }

    public function guardBypass($surveyId)
    {
        $flag = $this->get('guard_bypass', 'Survey', $surveyId, false);
        if ($flag) {
            $isAdmin = $this->isAdminUser($surveyId);
            if ($isAdmin) {
                return true;
            }
        }
        return false;
    }

    public function isAdminUser() {
        $AuthSAML = $this->pluginManager->loadPlugin('AuthSAML');
        $ssp = $AuthSAML->get_saml_instance();
        $ssp->requireAuth();

        $username = $AuthSAML->getUserNameAttribute();

        $oUser = $AuthSAML->api->getUserByName($username);

        // user object is null (not found)
        if (!$oUser) {
            return false;
        }

        return true;
    }

    public function getGlobalBasePermissions() {
        $this->getEvent()->append('globalBasePermissions',array(
            'plugin_settings' => array(
                'create' => false,
                'update' => true, // allow only update permission to display
                'delete' => false,
                'import' => false,
                'export' => false,
                'read' => false,
                'title' => gT("Save Plugin Settings"),
                'description' => gT("Allow user to save plugin settings"),
                'img' => 'usergroup'
            ),
        ));
    }
}
