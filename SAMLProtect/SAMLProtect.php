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
            $current = $this->get('auth_protection_enabled', 'Survey', $event->get('survey'));
            $event->set('surveysettings.' . $this->id, [
                'name' => get_class($this),
                'settings' => [
                    'auth_protection_enabled' => [
                        'type' => 'checkbox',
                        'label' => 'Enabled',
                        'help' => 'Only SAML users should see the survey ?',
                        'default' => false,
                        'current' => $current,
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
        $id = $event->get('surveyId');
        $flag = $this->get('auth_protection_enabled', 'Survey', $id);
        if ($flag) {
            // Check if user is authenticated
            $AuthSAML = $this->pluginManager->loadPlugin('AuthSAML');

            $ssp = $AuthSAML->get_saml_instance();

            $ssp->requireAuth();
        }
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
