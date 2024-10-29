<?php

class ActiveAuthSettings
{
    /**
     * Holds the values to be used in the fields callbacks
     */
    private $options;

    private $plugin_file;

    /**
     * Start up
     */
    public function __construct($plugin)
    {
        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
        add_filter('plugin_action_links', array($this, 'duo_add_link'), 10, 2);
        $this->plugin_file = $plugin;
    }

    public function duo_add_link($links, $file) {
        static $this_plugin;
        if (!$this_plugin) $this_plugin = $this->plugin_file;

        if ($file == $this_plugin) {
            $settings_link = '<a href="options-general.php?page=aca-settings">'.__("Settings", "aca-settings").'</a>';
            array_unshift($links, $settings_link);
        }
        return $links;
    }

    /**
     * Add options page
     */
    public function add_plugin_page()
    {
        // This page will be under "Settings"
        add_options_page(
            'Settings Active Auth',
            'Active Auth',
            'manage_options',
            'aca-settings',
            array($this, 'create_admin_page')
        );
    }


    /**
     * Options page callback
     */
    public function create_admin_page()
    {
        // Set class property
        $this->options = get_option('aca-options');
        ?>
        <div class="wrap">
            <h2>Active Auth Security</h2>
            <form method="post" action="options.php">
                <?php
                // This prints out all hidden setting fields
                settings_fields('aca_option_group');
                do_settings_sections('aca-settings');
                submit_button();
                ?>
            </form>
        </div>
    <?php
    }

    /**
     * Register and add settings
     */
    public function page_init()
    {
        register_setting(
            'aca_option_group', // Option group
            'aca-options', // Option name
            array($this, 'sanitize') // Sanitize
        );

        add_settings_section(
            'setting_section_id', // ID
            'My Settings', // Title
            array($this, 'print_section_info'), // Callback
            'aca-settings' // Page
        );

        add_settings_field(
            'aca_iaccount', // ID
            'Integration account', // Title
            array($this, 'aca_iaccount_callback'), // Callback
            'aca-settings', // Page
            'setting_section_id' // Section
        );
/*
        add_settings_field(
            'aca_server',
            'API hostname',
            array($this, 'aca_server_callback'),
            'aca-settings',
            'setting_section_id'
        );
*/
        add_settings_field(
            'aca_ikey',
            'Integration ID',
            array($this, 'aca_ikey_callback'),
            'aca-settings',
            'setting_section_id'
        );

        add_settings_field(
            'aca_skey',
            'Secret Key',
            array($this, 'aca_skey_callback'),
            'aca-settings',
            'setting_section_id'
        );

        add_settings_field(
            'aca_roles',
            'Enable for roles:',
            array($this, 'aca_roles_callback'),
            'aca-settings',
            'setting_section_id'
        );

        register_setting(
            'aca_option_group',
            'aca_roles',
            array($this, 'aca_roles_validate')
        );

        add_settings_field(
            'aca_enabled',
            'Enable two-factor authentication',
            array($this, 'aca_enabled_callback'),
            'aca-settings',
            'setting_section_id'
        );

    }


    function aca_roles_validate($options) {
        //return empty array
        if (!is_array($options) || empty($options) || (false === $options)) {
            return array();
        }

        global $wp_roles;
        $wp_roles = isset($wp_roles) ? $wp_roles : new WP_Roles();

        $valid_roles = $wp_roles->get_names();
        //otherwise validate each role and then return the array
        foreach ($options as $opt) {
            if (!in_array($opt, $valid_roles)) {
                unset($options[$opt]);
            }
        }
        return $options;
    }

    /**
     * Sanitize each setting field as needed
     * @param $input
     * @return array
     */
    public function sanitize($input)
    {
        $new_input = array();

        if(isset( $input['aca_iaccount']))
            $new_input['aca_iaccount'] = sanitize_text_field( $input['aca_iaccount'] );
/*
        if(isset( $input['aca_server']))
            $new_input['aca_server'] = sanitize_text_field( $input['aca_server'] );
*/
        if(isset( $input['aca_ikey']))
            $new_input['aca_ikey'] = sanitize_text_field( $input['aca_ikey'] );

        if(isset( $input['aca_skey']))
            $new_input['aca_skey'] = sanitize_text_field( $input['aca_skey'] );

        if(isset( $input['aca_enabled']))
            $new_input['aca_enabled'] = sanitize_text_field( $input['aca_enabled'] );

        return $new_input;
    }

    /**
     * Print the Section text
     */
    public function print_section_info()
    {
        print 'Enter your settings below:';
    }

    /**
     * Get the settings option array and print one of its values
     */
    public function aca_iaccount_callback()
    {
        printf(
            '<input type="text" id="aca_iaccount" name="aca-options[aca_iaccount]" value="%s" />',
            isset($this->options['aca_iaccount']) ? esc_attr($this->options['aca_iaccount']) : ''
        );
    }

    /**
     * Get the settings option array and print one of its values
     */
/*
    public function aca_server_callback()
    {
        printf(
            '<input type="text" id="aca_server" name="aca-options[aca_server]" value="%s" />',
            isset($this->options['aca_server']) ? esc_attr($this->options['aca_server']) : ''
        );
    }
*/
    /**
     * Get the settings option array and print one of its values
     */
    public function aca_ikey_callback()
    {
        printf(
            '<input type="text" id="aca_ikey" name="aca-options[aca_ikey]" value="%s" />',
            isset($this->options['aca_ikey']) ? esc_attr($this->options['aca_ikey']) : ''
        );
    }

    /**
     * Get the settings option array and print one of its values
     */
    public function aca_skey_callback()
    {
        printf(
            '<input type="text" id="aca_skey" name="aca-options[aca_skey]" value="%s" />',
            isset($this->options['aca_skey']) ? esc_attr($this->options['aca_skey']) : ''
        );
    }

    /**
     * Get the settings option array and print one of its values
     */
    public function aca_enabled_callback()
    {
        printf(
            '<input type="checkbox" id="aca_enabled" name="aca-options[aca_enabled]" value="1"'.($this->options['aca_enabled'] == 1 ? 'checked' : '').' /> Enable/Disable'
        );
    }

    /**
     * Get the settings option array and print one of its values
     */
    public function aca_roles_callback()
    {
        global $wp_roles;
        $wp_roles = isset($wp_roles) ? $wp_roles : new WP_Roles();

        $roles = $wp_roles->get_names();
        $newroles = array();

        foreach($roles as $key=>$role) {
            $newroles[$key] = $role;
        }

        $selected = get_option('aca_roles', $newroles);

        foreach ($wp_roles->get_names() as $key=>$role) {
        ?>
            <input id="aca_roles" name='aca_roles[<?php echo $key; ?>]' type='checkbox' value='<?php echo $role; ?>'  <?php if(in_array($role, $selected)) echo 'checked'; ?> /> <?php echo $role; ?> <br />
        <?php
        }
    }
}