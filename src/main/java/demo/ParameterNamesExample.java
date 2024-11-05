package demo;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

public class ParameterNamesExample {
    public void exampleMethod(String username, int age) { }

    public static void main(String[] args) throws NoSuchMethodException {

        Method method = ParameterNamesExample.class
                .getMethod("exampleMethod", String.class, int.class);

        for (Parameter parameter : method.getParameters()) {
            System.out.println("Parameter name: " + parameter.getName());
        }
    }
}