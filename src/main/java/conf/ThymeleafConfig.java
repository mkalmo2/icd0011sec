package conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.thymeleaf.spring5.SpringTemplateEngine;
import org.thymeleaf.spring5.view.ThymeleafViewResolver;
import org.thymeleaf.templateresolver.ServletContextTemplateResolver;

import javax.servlet.ServletContext;

@Configuration
public class ThymeleafConfig {

    @Bean
    public ServletContextTemplateResolver templateResolver(ServletContext ctx) {
        ServletContextTemplateResolver templateResolver =
                new ServletContextTemplateResolver(ctx);
        templateResolver.setPrefix("/WEB-INF/views/");
        templateResolver.setSuffix(".html");
        templateResolver.setTemplateMode("HTML5");

        return templateResolver;
    }

    @Bean
    public SpringTemplateEngine templateEngine(ServletContext ctx) {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(templateResolver(ctx));
        return templateEngine;
    }

    @Bean
    public ThymeleafViewResolver viewResolver(ServletContext ctx) {
        ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
        viewResolver.setTemplateEngine(templateEngine(ctx));
        viewResolver.setOrder(1);
        return viewResolver;
    }

}