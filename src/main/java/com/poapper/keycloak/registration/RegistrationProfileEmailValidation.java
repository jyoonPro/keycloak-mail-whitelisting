package com.poapper.keycloak.registration;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.forms.RegistrationProfile;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

public class RegistrationProfileEmailValidation extends RegistrationProfile implements FormAction {

   public static final String PROVIDER_ID = "registration-email-validation-action";

   @Override
    public String getDisplayType() {
        return "Registration Email Validation";
   }

   @Override
   public String getId() {
      return PROVIDER_ID;
   }

   @Override
    public boolean isConfigurable() {
        return true;
   }

   @Override
   public String getHelpText() {
      return "Adds validation of email domain names and characters for registration";
   }

   private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

   static {
      // Checks for email domain
      ProviderConfigProperty emailDomain = new ProviderConfigProperty();
      emailDomain.setName("validDomains");
      emailDomain.setLabel("Valid domains for emails");
      emailDomain.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
      emailDomain.setHelpText("List valid email domains authorized to register. Wildcard (*, default) allowed.");
      CONFIG_PROPERTIES.add(emailDomain);

      // Checks for characters in email names
      ProviderConfigProperty disallowedChar = new ProviderConfigProperty();
      disallowedChar.setName("disallowedChar");
      disallowedChar.setLabel("Disallowed characters in email name");
      disallowedChar.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
      disallowedChar.setHelpText("List disallowed characters (or strings). Example: \".\", \"-\", etc.");
      CONFIG_PROPERTIES.add(disallowedChar);
   }

   @Override
   public List<ProviderConfigProperty> getConfigProperties() {
      return CONFIG_PROPERTIES;
   }

   @Override
   public void validate(ValidationContext context) {
      MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

      List<FormMessage> errors = new ArrayList<>();
      String email = formData.getFirst(Validation.FIELD_EMAIL);

      boolean emailDomainValid = false;
      AuthenticatorConfigModel mailDomainConfig = context.getAuthenticatorConfig();
      String eventError = Errors.INVALID_REGISTRATION;

      if(email == null) {
         context.getEvent().detail(Details.EMAIL, null);
         errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.INVALID_EMAIL));
         context.error(eventError);
         context.validationError(formData, errors);
         return;
      }

      String[] domains = mailDomainConfig.getConfig().getOrDefault("validDomains","*").split("##");
      String[] disallowedChar = mailDomainConfig.getConfig().getOrDefault("disallowedChar", "").split("##");

      for (String domain : domains) {
         if (domain.equals("*") || email.endsWith(domain)) {
            emailDomainValid = true;
            break;
         }
      }

      String emailName = email.split("@")[0];
      for (String dc : disallowedChar) {
         if (emailName.contains(dc)) {
            emailDomainValid = false;
            break;
         }
      }

      if (!emailDomainValid) {
         context.getEvent().detail(Details.EMAIL, email);
         errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, Messages.INVALID_EMAIL));
      }

      if (errors.size() > 0) {
         context.error(eventError);
         context.validationError(formData, errors);

      } else {
         context.success();
      }
   }
}