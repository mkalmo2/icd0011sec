package user;

public class UserDao {

    public User getUserByUserName(String userName) {
        switch (userName) {
            case "user": return new User("user", "Anonymous User");
            case "jill": return new User("jill", "Jill Smith");
            case "jack": return new User("jack", "Jack Smith");
            default: return null;
        }
    }


}
