package com.aegis.shared.infrastructure;

import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Prefer the JPA {@code transactionManager} bean when Neo4j also registers a TM.
 */
@Configuration
public class TransactionManagerConfig {

    @Bean
    public static BeanFactoryPostProcessor jpaTransactionManagerPrimary() {
        return beanFactory -> {
            if (beanFactory.containsBeanDefinition("transactionManager")) {
                beanFactory.getBeanDefinition("transactionManager").setPrimary(true);
            }
        };
    }
}
