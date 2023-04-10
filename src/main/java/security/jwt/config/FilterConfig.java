package security.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import security.jwt.filter.MyFilter1;
import security.jwt.filter.MyFilter2;

@Configuration
public class FilterConfig {
    @Bean
    public FilterRegistrationBean<MyFilter1> filter1() {
        FilterRegistrationBean<MyFilter1> filter1 = new FilterRegistrationBean<>(new MyFilter1());
        filter1.addUrlPatterns("/*");
        filter1.setOrder(1);
        return filter1;
    }
    @Bean
    public FilterRegistrationBean<MyFilter2> filter2() {
        FilterRegistrationBean<MyFilter2> filter2 = new FilterRegistrationBean<>(new MyFilter2());
        filter2.addUrlPatterns("/*");
        filter2.setOrder(0);
        return filter2;
    }


}
