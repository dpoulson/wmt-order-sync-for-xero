<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
/**
 * Xero WooCommerce Admin Class
 * Manages the plugin's administration page, settings, and OAuth initiation.
 */
class Xero_Woo_Admin {

	private $api_manager;
	const PAGE_SLUG = 'wmt-order-sync-for-xero';

	public function __construct( Xero_API_Manager $api_manager ) {
		$this->api_manager = $api_manager;

		add_action( 'admin_menu', [ $this, 'add_plugin_menu' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );
		add_action( 'admin_init', [ $this, 'handle_oauth_callback' ] );
		add_action( 'admin_notices', [ $this, 'display_connection_notices' ] );
		add_action( 'wp_ajax_xero_disconnect', [ $this, 'handle_disconnect' ] );
	}

	/**
	 * Generates the dynamic redirect URI for the Xero App setup.
	 */
	private function get_redirect_uri() {
		return admin_url( 'admin.php?page=' . self::PAGE_SLUG );
	}

	/**
	 * Adds the plugin settings page to the WooCommerce menu.
	 */
	public function add_plugin_menu() {
		add_submenu_page(
			'woocommerce',
			__( 'Xero Invoicing Settings', 'wmt-order-sync-for-xero' ),
			__( 'Xero Invoicing', 'wmt-order-sync-for-xero' ),
			'manage_options',
			self::PAGE_SLUG,
			[ $this, 'plugin_settings_page' ]
		);
	}

	/**
	 * Registers all plugin settings for saving.
	 */
	public function register_settings() {
		// Core Settings (Client ID, etc.)
		register_setting( 
			'xero_woo_settings_group', 
			'xero_client_id', 
			[
				'type'			  => 'string',
				'sanitize_callback' => 'sanitize_text_field', // Use for simple, single-line text input
			]
		);
		
		register_setting( 
			'xero_woo_settings_group', 
			'xero_default_sales_account', 
			[
				'type'			  => 'string',
				'sanitize_callback' => 'sanitize_text_field', // Use for single-line text input
			]
		);
		
		register_setting( 
			'xero_woo_settings_group', 
			'xero_payment_mappings', 
			[
				'type'			  => 'array',
				// Use a custom function to loop through and sanitize each array element
				'sanitize_callback' => [ $this, 'sanitize_array_recursively' ], 
			]
		);
	}

	/**
	 * Custom sanitization callback to clean an array of settings (like payment mappings).
	 * * @param array $input The raw array input from the settings form.
	 * @return array The sanitized array.
	 */
	public function sanitize_array_recursively( $input ) {
		$output = [];
		if ( is_array( $input ) ) {
			foreach ( $input as $key => $value ) {
				// Sanitize the key and value of each mapping entry
				$sanitized_key   = sanitize_text_field( $key );
				$sanitized_value = sanitize_text_field( $value );
				
				// Check if both key and value are valid after sanitization
				if ( ! empty( $sanitized_key ) && ! empty( $sanitized_value ) ) {
					$output[ $sanitized_key ] = $sanitized_value;
				}
			}
		}
		return $output;
	}

	/**
	 * Handles the redirect from Xero after authorization.
	 */
	public function handle_oauth_callback() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['page'] ) && $_GET['page'] === self::PAGE_SLUG && isset( $_GET['code'] ) ) {
			
			// Verify the state parameter to prevent CSRF
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$received_state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
			
			// Verify state against stored transient for the current user
			$user_id = get_current_user_id();
			$stored_state   = get_transient( 'xero_oauth_state_' . $user_id );
			delete_transient( 'xero_oauth_state_' . $user_id );

			if ( empty( $stored_state ) || $received_state !== $stored_state ) {
				wp_die( esc_html__( 'Security check failed: Invalid OAuth state.', 'wmt-order-sync-for-xero' ) );
			}

			// Clear the state transient once verified
			delete_transient( 'xero_oauth_state' );

			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$code = sanitize_text_field( wp_unslash( $_GET['code'] ) );
			$redirect_uri = $this->get_redirect_uri();

			if ( $this->api_manager->handle_oauth_redirect( $code, $redirect_uri ) ) {
				// Clear PKCE verifier after successful exchange
				delete_option( Xero_API_Manager::VERIFIER_OPTION_KEY );
				wp_safe_redirect( add_query_arg( 'xero_connected', '1', $redirect_uri ) );
				exit;
			} else {
				wp_safe_redirect( add_query_arg( 'xero_connected', '0', $redirect_uri ) );
				exit;
			}
		}
	}

	/**
	 * Handles the AJAX disconnect request.
	 */
	public function handle_disconnect() {
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( 'xero_disconnect_nonce', 'security' ) ) {
			wp_send_json_error( __( 'Permission denied.', 'wmt-order-sync-for-xero' ) );
		}

		delete_option( Xero_API_Manager::TOKEN_OPTION_KEY );
		delete_option( 'xero_tenant_id' );
		delete_option( Xero_API_Manager::VERIFIER_OPTION_KEY );
		delete_option( Xero_API_Manager::CLIENT_ID_KEY );

		wp_send_json_success( __( 'Disconnected from Xero.', 'wmt-order-sync-for-xero' ) );
	}

	/**
	 * Displays connection status notices.
	 */
	public function display_connection_notices() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['xero_connected'] ) && current_user_can( 'manage_options' ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$connected = sanitize_text_field( wp_unslash( $_GET['xero_connected'] ) );
			if ( '1' === $connected ) {
				echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Successfully connected to Xero!', 'wmt-order-sync-for-xero' ) . '</p></div>';
			} elseif ( '0' === $connected ) {
				echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Failed to connect to Xero. Check your Client ID and Redirect URI setup.', 'wmt-order-sync-for-xero' ) . '</p></div>';
			}
		}
	}

	/**
	 * Renders the main settings page content.
	 */
	public function plugin_settings_page() {
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Order Sync For Xero', 'wmt-order-sync-for-xero' ); ?></h1>
			<form method="post" action="options.php">
				<?php settings_fields( 'xero_woo_settings_group' ); ?>
				<?php do_settings_sections( 'xero_woo_settings_group' ); ?>

				<h2><?php echo esc_html__( '1. Xero API Connection', 'wmt-order-sync-for-xero' ); ?></h2>
				<?php $this->render_oauth_connection_status(); ?>

				<h2><?php echo esc_html__( '2. Default Accounting Settings', 'wmt-order-sync-for-xero' ); ?></h2>
				<?php $this->render_default_accounts_section(); ?>

				<h2><?php echo esc_html__( '3. Payment Method Mapping', 'wmt-order-sync-for-xero' ); ?></h2>
				<?php $this->render_payment_mapping_section(); ?>

				<?php submit_button(); ?>
			</form>
		</div>
		<?php
		$this->render_admin_scripts();
	}

	/**
	 * Renders the Client ID input and OAuth connection button/status.
	 */
	private function render_oauth_connection_status() {
		$access_token = $this->api_manager->get_valid_access_token();
		$redirect_uri = $this->get_redirect_uri();
		$client_id = get_option( Xero_API_Manager::CLIENT_ID_KEY );
		$tenant_id = get_option( 'xero_tenant_id' );
		$tenant_status = $tenant_id ? __( 'Connected', 'wmt-order-sync-for-xero' ) : __( 'Tenant ID not found. Try reconnecting.', 'wmt-order-sync-for-xero' );

		echo '<table class="form-table">';

		// Client ID Input Field
		echo '<tr><th><label for="xero_client_id">' . esc_html__( 'Client ID (PKCE)', 'wmt-order-sync-for-xero' ) . '</label></th><td>';
		printf(
			'<input type="text" id="xero_client_id" name="%s" value="%s" class="regular-text" placeholder="%s" />',
			esc_attr( Xero_API_Manager::CLIENT_ID_KEY ),
			esc_attr( $client_id ),
			esc_attr__( 'Enter your Xero Application Client ID', 'wmt-order-sync-for-xero' )
		);
		echo '<p class="description">' . esc_html__( 'Your Client ID from the Xero Developer Portal. Since you are using PKCE, no secret is required.', 'wmt-order-sync-for-xero' ) . '</p>';
		echo '</td></tr>';

		// Dynamic Redirect URI Display
		echo '<tr><th><label>' . esc_html__( 'Redirect URI', 'wmt-order-sync-for-xero' ) . '</label></th><td>';
		printf(
			'<code style="background-color: #f3f3f3; padding: 5px 10px; border: 1px solid #ccc; display: inline-block;">%s</code>',
			esc_html( $redirect_uri )
		);
		echo '<p class="description">' . esc_html__( 'Copy this URL exactly into the "Redirect URI" field in your Xero App settings.', 'wmt-order-sync-for-xero' ) . '</p>';
		echo '</td></tr>';

		// Connection Status and Button
		echo '<tr><th>' . esc_html__( 'Connection Status', 'wmt-order-sync-for-xero' ) . '</th><td>';
		if ( $access_token ) {
			echo '<span style="color: green; font-weight: bold;">' . esc_html__( 'CONNECTED', 'wmt-order-sync-for-xero' ) . '</span><br>';
			echo '<p>' . esc_html__( 'Tenant ID Status: ', 'wmt-order-sync-for-xero' ) . esc_html( $tenant_status ) . '</p>';
			echo '<button type="button" id="xero-disconnect-btn" class="button button-secondary">' . esc_html__( 'Disconnect Xero', 'wmt-order-sync-for-xero' ) . '</button>';
		} else {
			if ( empty( $client_id ) ) {
				 echo '<span style="color: red; font-weight: bold;">' . esc_html__( 'DISCONNECTED', 'wmt-order-sync-for-xero' ) . '</span> ' . esc_html__( '(Please save your Client ID first)', 'wmt-order-sync-for-xero' );
			} else {
				$auth_url = $this->api_manager->generate_auth_url( $redirect_uri );
				echo '<a href="' . esc_url( $auth_url ) . '" class="button button-primary">' . esc_html__( 'Connect to Xero App', 'wmt-order-sync-for-xero' ) . '</a>';
				echo '<p class="description">' . esc_html__( 'You must save your Client ID above before connecting.', 'wmt-order-sync-for-xero' ) . '</p>';
			}
		}
		echo '</td></tr>';

		echo '</table>';
	}

	/**
	 * Renders the section for default account code setup.
	 */
	private function render_default_accounts_section() {
		$current_code = get_option( 'xero_default_sales_account', '' );

		// Fetch real sales accounts from Xero API
		$xero_sales_accounts = $this->api_manager->get_sales_accounts();
		$is_connected = ! empty( $xero_sales_accounts );

		echo '<table class="form-table"><tr><th><label for="xero_default_sales_account">' . esc_html__( 'Default Sales Account Code', 'wmt-order-sync-for-xero' ) . '</label></th><td>';

		if ( ! $is_connected ) {
			// Show connection warning and a disabled select or text input
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'Warning:', 'wmt-order-sync-for-xero' ) . '</strong> ' . esc_html__( 'You must be connected to Xero to fetch Sales Account Codes. Please connect in Section 1.', 'wmt-order-sync-for-xero' ) . '</p></div>';
			
			// Add a placeholder/empty option if disconnected to display the message
			$xero_sales_accounts = [ '000' => __( 'Accounts not fetched (Disconnected)', 'wmt-order-sync-for-xero' ) ];
		}

		// Render the select dropdown
		echo '<select id="xero_default_sales_account" name="xero_default_sales_account" class="regular-text" ' . ( $is_connected ? '' : 'disabled' ) . '>';
		echo '<option value="">' . esc_html__( '-- Select Sales Account --', 'wmt-order-sync-for-xero' ) . '</option>';

		// Populate dropdown with fetched Xero Sales Accounts
		foreach ( $xero_sales_accounts as $code => $name ) {
			printf(
				'<option value="%s" %s>%s</option>',
				esc_attr( $code ),
				selected( $current_code, $code, false ),
				esc_html( $name )
			);
		}
		echo '</select>';

		echo '<p class="description">' . esc_html__( 'The default Xero Account Code for product sales (Revenue). Accounts are dynamically pulled from your connected Xero organization.', 'wmt-order-sync-for-xero' ) . '</p>';
		echo '</td></tr></table>';
	}

	/**
	 * Renders the WooCommerce Payment Method to Xero Bank Account mapping table.
	 */
	private function render_payment_mapping_section() {
		$payment_gateways = WC()->payment_gateways->payment_gateways();
		$mappings = get_option( 'xero_payment_mappings', [] );

		// Fetch real bank accounts from Xero API
		$xero_bank_accounts = $this->api_manager->get_bank_accounts();
		$is_connected = ! empty( $xero_bank_accounts );

		if ( empty( $payment_gateways ) ) {
			echo '<p>' . esc_html__( 'No active WooCommerce payment gateways found.', 'wmt-order-sync-for-xero' ) . '</p>';
			return;
		}

		if ( ! $is_connected ) {
			echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'Warning:', 'wmt-order-sync-for-xero' ) . '</strong> ' . esc_html__( 'You must be connected to Xero to fetch and map Bank Accounts. Please connect in Section 1.', 'wmt-order-sync-for-xero' ) . '</p></div>';
			// Fallback: If disconnected, show a disabled table but don't stop rendering
			$xero_bank_accounts = [ '000' => __( 'Accounts not fetched (Disconnected)', 'wmt-order-sync-for-xero' ) ];
		}

		echo '<table class="wp-list-table widefat fixed striped">';
		echo '<thead><tr><th>' . esc_html__( 'WooCommerce Payment Method', 'wmt-order-sync-for-xero' ) . '</th><th>' . esc_html__( 'Xero Bank Account Code', 'wmt-order-sync-for-xero' ) . '</th></tr></thead>';
		echo '<tbody>';

		foreach ( $payment_gateways as $id => $gateway ) {
			if ( 'yes' === $gateway->enabled ) {
				$current_mapping = $mappings[ $id ] ?? '';
				echo '<tr>';
				echo '<td>' . esc_html( $gateway->get_method_title() ) . ' (' . esc_html( $id ) . ')</td>';
				echo '<td>';
				echo '<select name="xero_payment_mappings[' . esc_attr( $id ) . ']" ' . ( $is_connected ? '' : 'disabled' ) . '>';
				echo '<option value="">' . esc_html__( '-- Select Xero Account --', 'wmt-order-sync-for-xero' ) . '</option>';

				// Populate dropdown with fetched Xero Bank Accounts
				foreach ( $xero_bank_accounts as $code => $name ) {
					printf(
						'<option value="%s" %s>%s</option>',
						esc_attr( $code ),
						selected( $current_mapping, $code, false ),
						esc_html( $name )
					);
				}
				echo '</select>';
				echo '</td>';
				echo '</tr>';
			}
		}

		echo '</tbody></table>';
		if ( $is_connected ) {
			 echo '<p class="description">' . esc_html__( 'Map each active WooCommerce payment method to the corresponding Xero Bank Account code where the funds are deposited. Accounts are dynamically pulled from your connected Xero organization.', 'wmt-order-sync-for-xero' ) . '</p>';
		} else {
			 echo '<p class="description">' . esc_html__( 'Once connected to Xero, the available bank accounts will appear in the dropdown menus above.', 'wmt-order-sync-for-xero' ) . '</p>';
		}
	}

	/**
	 * Renders inline scripts for AJAX disconnect.
	 */
	private function render_admin_scripts() {
		?>
		<script>
			jQuery(document).ready(function($) {
				$('#xero-disconnect-btn').on('click', function(e) {
					e.preventDefault();
					if (confirm('<?php echo esc_js( __( 'Are you sure you want to disconnect from Xero? This will remove all stored tokens.', 'wmt-order-sync-for-xero' ) ); ?>')) {
						var $button = $(this);
						$button.prop('disabled', true).text('<?php echo esc_js( __( 'Disconnecting...', 'wmt-order-sync-for-xero' ) ); ?>');

						$.ajax({
							url: ajaxurl,
							type: 'POST',
							data: {
								action: 'xero_disconnect',
								security: '<?php echo esc_attr( wp_create_nonce( 'xero_disconnect_nonce' ) ); ?>'
							},
							success: function(response) {
								if (response.success) {
									alert('<?php echo esc_js( __( 'Successfully disconnected. Refreshing page...', 'wmt-order-sync-for-xero' ) ); ?>');
									window.location.reload();
								} else {
									alert('<?php echo esc_js( __( 'Disconnect failed: ', 'wmt-order-sync-for-xero' ) ); ?>' + (response.data || '<?php echo esc_js( __( 'Unknown error', 'wmt-order-sync-for-xero' ) ); ?>'));
									$button.prop('disabled', false).text('<?php echo esc_js( __( 'Disconnect Xero', 'wmt-order-sync-for-xero' ) ); ?>');
								}
							},
							error: function() {
								alert('<?php echo esc_js( __( 'An error occurred during AJAX call.', 'wmt-order-sync-for-xero' ) ); ?>');
								$button.prop('disabled', false).text('<?php echo esc_js( __( 'Disconnect Xero', 'wmt-order-sync-for-xero' ) ); ?>');
							}
						});
					}
				});
			});
		</script>
		<?php
	}
}
