package com.aarteaga.gateway.server.filters.factory;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

@Component
public class EjemploGatewayFilterFactory extends AbstractGatewayFilterFactory<EjemploGatewayFilterFactory.Configuration>{
	
	private static Logger logger = LoggerFactory.getLogger(EjemploGatewayFilterFactory.class);

	public EjemploGatewayFilterFactory() {
		super(Configuration.class);
	}

	@Override
	public GatewayFilter apply(Configuration config) {
		return (exchange, chain) -> {
			logger.info("ejecutando pre gateway filter factory: " + config.mensaje);
			
			return chain.filter(exchange).then(Mono.fromRunnable(() -> {
				
				Optional.ofNullable(config.cookieValor).ifPresent(cookie -> {
					exchange.getResponse().addCookie(ResponseCookie.from(config.cookieNombre, cookie).build());
				});
				logger.info("ejecutando post gateway filter factory: " + config.mensaje);
			}));
		};
	}
	
	@Override
	public String name() {
		//Renombramos el valor del filtro de Ejemplo a EjemploCookie, se debe actualizar el nombre en el .yml
		return "EjemploCookie";
	}
	
	@Override
	public List<String> shortcutFieldOrder(){
		return Arrays.asList("mensaje", "cookieNombre", "cookieValor");
	}
	
	public static class Configuration{
		private String mensaje;
		private String cookieValor;
		private String cookieNombre;
		public String getMensaje() {
			return mensaje;
		}
		public void setMensaje(String mensaje) {
			this.mensaje = mensaje;
		}
		public String getCookieValor() {
			return cookieValor;
		}
		public void setCookieValor(String cookieValor) {
			this.cookieValor = cookieValor;
		}
		public String getCookieNombre() {
			return cookieNombre;
		}
		public void setCookieNombre(String cookieNombre) {
			this.cookieNombre = cookieNombre;
		}
	}
}
