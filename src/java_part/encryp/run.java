package encryp;
import encryp.PerforcePasswordEncryptor;

public class run {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		PerforcePasswordEncryptor eny = new PerforcePasswordEncryptor();
		if(args[0].equals("-en"))
		{
			System.out.println(eny.encryptString(args[1]));
		}
		else if(args[0].equals("-de"))
		{
			System.out.println(eny.decryptString(args[1]));
		}
		else
		{
			System.out.println("invalid input");
		}
	}
}
