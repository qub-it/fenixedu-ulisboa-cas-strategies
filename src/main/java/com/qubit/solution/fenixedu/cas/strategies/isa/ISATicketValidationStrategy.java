/**
 * This file was created by Quorum Born IT <http://www.qub-it.com/> and its
 * copyright terms are bind to the legal agreement regulating the FenixEdu@ULisboa
 * software development project between Quorum Born IT and Serviços Partilhados da
 * Universidade de Lisboa:
 *  - Copyright © 2016 Quorum Born IT (until any Go-Live phase)
 *  - Copyright © 2016 Universidade de Lisboa (after any Go-Live phase)
 *
 * Contributors: paulo.abrantes@qub-it.com
 *
 *
 * This file is part of FenixEdu fenixedu-ulisboa-cas-strategies.
 *
 * FenixEdu fenixedu-ulisboa-cas-strategies is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * FenixEdu fenixedu-ulisboa-cas-strategies is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with FenixEdu fenixedu-ulisboa-cas-strategies.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.qubit.solution.fenixedu.cas.strategies.isa;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.fenixedu.academic.domain.Person;
import org.fenixedu.bennu.cas.client.CASClientConfiguration;
import org.fenixedu.bennu.core.domain.User;
import org.fenixedu.bennu.core.domain.UsernameHack;
import org.fenixedu.bennu.core.domain.exceptions.AuthorizationException;
import org.fenixedu.bennu.core.security.Authenticate;
import org.fenixedu.ulisboa.specifications.service.cas.TicketValidationStrategy;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.qubit.solution.fenixedu.cas.strategies.fcul.FculTicketValidationStrategy;
import com.qubit.solution.fenixedu.integration.ldap.service.LdapIntegration;

import pt.ist.fenixframework.CallableWithoutException;
import pt.ist.fenixframework.FenixFramework;

public class ISATicketValidationStrategy implements TicketValidationStrategy {

    private static final Logger logger = LoggerFactory.getLogger(FculTicketValidationStrategy.class);

    private final TicketValidator validator =
            new Cas30ServiceTicketValidator(CASClientConfiguration.getConfiguration().casServerUrl());

    @Override
    public void validateTicket(final String ticket, String requestURL, final HttpServletRequest request,
            final HttpServletResponse response) throws TicketValidationException, AuthorizationException {

        Authenticate.logout(request, response);
        requestURL = requestURL.replace("http:", "https:");
        Assertion validate = validator.validate(ticket, requestURL);
        String username = validate.getPrincipal().getName().trim().toLowerCase();
        User user = User.findByUsername(username);

        if (user == null) {
            String previousUsername = (String) validate.getPrincipal().getAttributes().get("previousUsername");
            final String institutionalMail = (String) validate.getPrincipal().getAttributes().get("mail");
            Person person = Person.findByUsername(previousUsername);

            if (person == null) {
                logger.error("Received valid username: " + username
                        + " from CAS. User was not found look up by previous username: " + previousUsername);
                throw AuthorizationException.authenticationFailed();
            } else {
                if (!LdapIntegration.changeCN(person, username)) {
                    logger.error("Unable to align: " + person.getUsername() + " to CN provided by CAS: " + username
                            + " Falling back to fenix username");
                    username = person.getUsername();
                } else {
                    LdapIntegration.removePassword(username);
                    final String finalUsername = username;
                    FenixFramework.getTransactionManager().withTransaction(new CallableWithoutException<Object>() {

                        @Override
                        public Object call() {
                            UsernameHack.changeUsername(person.getUsername(), finalUsername);
                            if (institutionalMail != null && institutionalMail.length() > 0) {
                                person.setInstitutionalEmailAddressValue(institutionalMail);
                            }
                            return null;
                        }
                    });
                }
            }
        }
        Authenticate.login(request, response, User.findByUsername(username), "TODO: CHANGE ME");
    }
}
