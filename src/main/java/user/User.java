package user;

public class User {

    private String userName;

    private String name;

    public String getUserName() {
        return userName;
    }

    public String getName() {
        return name;
    }

    public User(String userName, String name) {
        this.userName = userName;
        this.name = name;
    }

    @Override
    public String toString() {
        return "User{" +
                "userName='" + userName + '\'' +
                ", name='" + name + '\'' +
                '}';
    }
}
