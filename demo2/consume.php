<?php
/**
 * SAMPLE Code to demonstrate how to handle a SAML assertion response.
 *
 * The URL of this file will have been given during the SAML authorization.
 * After a successful authorization, the browser will be directed to this
 * link where it will send a certified response via $_POST.
 */

require_once '../_toolkit_loader.php';

try {
    if (isset($_POST['SAMLResponse']) && wp_verify_nonce(isset($_SERVER['nonce']),'SAMLResponse')) { 
        $samlSettings = new OneLogin_Saml2_Settings();
        $samlResponse = new OneLogin_Saml2_Response($samlSettings, $_POST['SAMLResponse']);
        if ($samlResponse->isValid()) {
            echo 'You are: ' . esc_attr($samlResponse->getNameId()) . '<br>';
            $attributes = $samlResponse->getAttributes();
            if (!empty($attributes)) {
                echo 'You have the following attributes:<br>';
                echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
                foreach ($attributes as $attributeName => $attributeValues) {
                    echo '<tr><td>' . esc_attr($attributeName) . '</td><td><ul>';
                    foreach ($attributeValues as $attributeValue) {
                        echo '<li>' . esc_attr($attributeValue) . '</li>';
                    }
                    echo '</ul></td></tr>';
                }
                echo '</tbody></table>';
            }
        } else {
            echo 'Invalid SAML Response';
        }
    } else {
        echo 'No SAML Response found in POST.';
    }
} catch (Exception $e) {
    echo 'Invalid SAML Response: ' . esc_attr($e->getMessage());
}
