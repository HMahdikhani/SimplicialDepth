import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;

import org.omg.PortableInterceptor.SYSTEM_EXCEPTION;
public class twoD {
	public static ArrayList<String> arrTxtLines=new ArrayList<String>();
	public static ArrayList<vector> arrData=new ArrayList<vector>();
	public static ArrayList<vector> arrTest=new ArrayList<vector>();
	public static void main(String[] args)
	{	
		dataFile();
		dataTest();	
	  for(vector vtest:arrTest)
    	{
	    vector theta=new vector();
	    theta.setX(1000.0*vtest.getX());
	    theta.setY(1000.0*vtest.getY());
		System.out.println(depth(arrData,theta));
    	}
	}
	public static double depth(ArrayList<vector> v, vector theta)
	{
		double Simplicial_D_theta=0;
		for(Integer i=0;i<= v.size()-1;i++)
		{
				vector v1=v.get(i);
				for(Integer j=0;j<i;j++)
				{
					vector v2=v.get(j);
					for (Integer k=0;k<j;k++)
					{
						vector v3=v.get(k);
				      	double alpha = ((v2.getY() - v3.getY())*(theta.getX() - v3.getX()) + (v3.getX() - v2.getX())*(theta.getY() - v3.getY())) /
					        ((v2.getY() - v3.getY())*(v1.getX() - v3.getX()) + (v3.getX() - v2.getX())*(v1.getY() - v3.getY()));
				    	double beta = ((v3.getY() - v1.getY())*(theta.getX() - v3.getX()) + (v1.getX() - v3.getX())*(theta.getY() - v3.getY())) /
					       ((v2.getY() - v3.getY())*(v1.getX() - v3.getX()) + (v3.getX() - v2.getX())*(v1.getY() - v3.getY()));
				    	double gamma = 1 - alpha - beta;
				    	//System.out.println(alpha);
				    	//system.out.println(beta);
					    //System.out.println(gamma);
				    	if (alpha>=0 && beta>=0 && gamma>=0)
				    	{
				            Simplicial_D_theta=Simplicial_D_theta+1;
				        }
		            }
				}
		}
		//Normalizing the depth
		double vsize=v.size();		
		Simplicial_D_theta=Simplicial_D_theta/((vsize*(vsize-1)*(vsize-2))/6);	
		// in the following form I got size overflow and multiplication of
		//three positive number were negative !   
		//Simplicial_D_theta=Simplicial_D_theta/(((v.size())*(v.size()-1)*(v.size()-2))/6); 
		return Simplicial_D_theta;
	}
public static void dataFile() {
	File file = new File("C:/Dataset.txt");
    FileInputStream fis = null;
    BufferedInputStream bis = null;
    DataInputStream dis = null;

    try {
      fis = new FileInputStream(file);

      // Here BufferedInputStream is added for fast reading.
      bis = new BufferedInputStream(fis);
      dis = new DataInputStream(bis);

      // dis.available() returns 0 if the file does not have more lines.
      while (dis.available() != 0) {
    	  String[] temp=dis.readLine().split(",");
    	  vector vtest=new vector();
			vtest.setX(1000.0*Double.parseDouble(temp[0]));
			vtest.setY(1000.0*Double.parseDouble(temp[1]));
			arrData.add(vtest);
      }

      // dispose all the resources after using them.
      fis.close();
      bis.close();
      dis.close();

    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }	
}
public static void dataTest() {
	File file = new File("C:/Theta.txt");
    FileInputStream fis = null;
    BufferedInputStream bis = null;
    DataInputStream dis = null;

    try 
    {
      fis = new FileInputStream(file);
      // Here BufferedInputStream is added for fast reading.
      bis = new BufferedInputStream(fis);
      dis = new DataInputStream(bis);
      // dis.available() returns 0 if the file does not have more lines.
         while (dis.available() != 0)
         {
    	   String[] temp=dis.readLine().split(",");
    	   vector vtest=new vector();
		   vtest.setX((Double.parseDouble(temp[0]) ));
		   vtest.setY(Double.parseDouble(temp[1]));
		   arrTest.add(vtest);
         }
         // dispose all the resources after using them.
         fis.close();
         bis.close();
         dis.close();

    }
    catch (FileNotFoundException e) 
    {
      e.printStackTrace();
    }
    catch (IOException e)
    {
     e.printStackTrace();
    }	
  }
}