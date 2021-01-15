// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <ctime>
#include <time.h>

#include "seal/seal.h"

using namespace std;
using namespace seal;

struct fPoint{ //Points with floating point values.
  float x,y;
  fPoint(){x=0.0f;y=0.0f;}
};

struct iPoint{ //Point with inetegr values.
  int x,y;
  iPoint(){x=0;y=0;}
};

struct pPoint{ //Point in plaintext mode.
  Plaintext x,y;
};

struct cPoint{ //Point in ciphertext mode.
  Ciphertext x,y;
};

struct cABG{ //Ciphertext αβγ to make a decision that a a query point is inside or outside a convex haul.
  Ciphertext alfa,beta,gamma;
};

vector<fPoint> readDataFromFile(string dataPath, int n);
Ciphertext detCompute(Evaluator &eval, cPoint M, cPoint N);
Ciphertext detCompute(Evaluator &eval, cPoint A, cPoint B, cPoint C);
void print_parameters(shared_ptr<SEALContext> context);



int main(int argc, char* argv[]){

  if(argc!=4) {cout << "Invalid arguments!!!" << endl; exit(0);}
  int dsSize = stoi(argv[1]); //dataset size
  int qrySize = stoi(argv[2]); //query size
  int scaleFactor = stoi(argv[3]); //scale factor 10,100,1000,10000

  srand(time(NULL));
  int c = 0;//temp counter
  //Read dataset and query point(s) from input file.
  //Read datatset and convert into integer.
  vector<fPoint> fDS = readDataFromFile("dataset.txt",dsSize);//read dataset with float values
  vector<iPoint> iDS; //dataset with integer values
  for (int i=0; i<dsSize; i++){//convert dataset from float to int
    iDS.push_back(iPoint());
    iDS[i].x = (int) (scaleFactor*fDS[i].x);
    iDS[i].y = (int) (scaleFactor*fDS[i].y);
    //cout << "(" <<  iDS[i].x << ", " << iDS[i].y << ")" << endl;
  }
  //Read query point(s) and convert into integer.
  vector<fPoint> fQry = readDataFromFile("query.txt",qrySize);//read query point(s) with float values
  vector<iPoint> iQry; //Query point(s) with integer values
  for (int i=0; i<qrySize; i++){//convert query point(s) from float to int
    iQry.push_back(iPoint());
    iQry[i].x = (int) (scaleFactor*fQry[i].x);
    iQry[i].y = (int) (scaleFactor*fQry[i].y);
    //cout << "(" <<  iQry[i].x << ", " << iQry[i].y << ")" << endl;
  }
  ///////////////////////////////////////////////////////////////////////////////////////////////////


  //Setup encryption scheme
  EncryptionParameters parms(scheme_type::BFV);
  parms.set_poly_modulus_degree(512);
  parms.set_coeff_modulus(coeff_modulus_128(4096));
  parms.set_plain_modulus(256);
  auto context = SEALContext::Create(parms);
  //print_parameters(context);
  IntegerEncoder encoder(parms.plain_modulus());
  KeyGenerator keygen(context);
  PublicKey public_key = keygen.public_key();
  SecretKey secret_key = keygen.secret_key();
  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);
  ///////////////////////////////////////////////



  //Convert integer dataset and query point(s) into plaintext.
  //Dataset conversion from integer intp plaintext.
  vector <pPoint> pDS; //convert integer dataset into plaintext mode.
  for (int i=0; i<dsSize; i++){
    pDS.push_back(pPoint());
    pDS[i] = {encoder.encode(iDS[i].x), encoder.encode(iDS[i].y)};
  }
  //Querypoint conversion from integer intp plaintext.
  vector <pPoint> pQry; //convert integer query point(s) into plaintext mode.
  for (int i=0; i<qrySize; i++){
    pQry.push_back(pPoint());
    pQry[i] = {encoder.encode(iQry[i].x), encoder.encode(iQry[i].y)};
  }
  //////////////////////////////////////////////////////////////////////////



  //Convert plaintext dataset and query point(s) into ciphertext.
  //Dataset conversion from plaintext into ciphertext.
  vector <cPoint> cDS; //convert dataset into ciphertext mode.
  for (int i=0; i<dsSize; i++){
    cDS.push_back(cPoint());
    encryptor.encrypt(pDS[i].x, cDS[i].x);
    encryptor.encrypt(pDS[i].y, cDS[i].y);
  }
  //Querypoint conversion from plaintext into ciphertext.
  vector <cPoint> cQry; //convert query point(s) into ciphertext mode.
  for (int i=0; i<qrySize; i++){
    cQry.push_back(cPoint());
    encryptor.encrypt(pQry[i].x, cQry[i].x);
    encryptor.encrypt(pQry[i].y, cQry[i].y);
  }
  ////////////////////////////////////////////////////////////////////


  //Print converted floating point into integer then plaintext and finally ciphertext values.
  //Print dataset conversions and release allocated memory.
  /*
  for (int i=0; i<dsSize; i++){
    cout << "Data(" <<  fDS[i].x << ", " << fDS[i].y  << ") --> (" <<  iDS[i].x << ", " << iDS[i].y  << ") --> (" <<  pDS[i].x.to_string() << ", " << pDS[i].y.to_string() << ") --> (E(x[" << i+1 << "]), E(y[" << i+1 << "]))" << endl;
  }
  */
  vector<fPoint>().swap(fDS);//release memory - floating point dataset
  vector<iPoint>().swap(iDS);//release memory - integer dataset
  vector<pPoint>().swap(pDS);//release memory - plaintext dataset

  //Print query point(s) conversions and release allocated memory.
  /*
  for (int i=0; i<qrySize; i++){
    cout << "Query(" <<  fQry[i].x << ", " << fQry[i].y  << ") --> (" <<  iQry[i].x << ", " << iQry[i].y  << ") --> (" <<  pQry[i].x.to_string() << ", " << pQry[i].y.to_string() << ") --> (E(x[" << i+1 << "]), E(y[" << i+1 << "]))" << endl;
  }
  */
  vector<fPoint>().swap(fQry);//release memory - floating point query point(s)
  vector<iPoint>().swap(iQry);//release memory - integer query point(s)
  vector<pPoint>().swap(pQry);//release memory - plaintext query point(s)
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////





  clock_t tStart = clock();

  //Calculating ciphertext values α, β and γ in order to decide that the query point is inside or outside the triangle.
  c = 0; //temp counter
  Plaintext tmpP;
  Ciphertext cAlfa, cBeta, cGamma;
  Ciphertext tmpC1, tmpC2, tmpC3;
  Plaintext pRnd;
  //Ciphertext cRnd;
  vector <cABG> cDecide;
  long iAlfa, iBeta, iGamma;
  int flag; //Counting query points inside the triangle.
  double flags[qrySize];
  for(int q=0; q<qrySize; q++){

    //Empty cDecide before starting each query point.
    //vector<cABG>().swap(cDecide);
    c = 0; //reset cDecide's counter for each query point;
    flag = 0; //reset floag counter for points inside the convex haul.

    for(int i=0; i<dsSize; i++)
      for(int j=i+1; j<dsSize; j++)
        for(int k=j+1; k<dsSize; k++){
          //cDecide.push_back(cABG());
          //cDecide[] = {alfa, beta, gamma}
          //For given points a,b and c with corresponding indexes a=i,b=j,c=k.
          //det(b-a, c-a) has been precomputed.
          //α =        det(b-a,c-a) * (det(q-a,c-a)
          //β = (-1) * det(b-a,c-a) * (det(q-a,b-a)
          //γ = det(b-a,c-a)^2 - α - β

          //Plaintext p;
          tmpC1 = detCompute(evaluator, cDS[i], cDS[j], cDS[k]);//det(b-a,c-a)
          tmpC2 = detCompute(evaluator, cDS[i], cQry[q], cDS[k]);//det(q-a,c-a) >>> to compute alfa
          tmpC3 = detCompute(evaluator, cDS[i], cQry[q], cDS[j]);//det(q-a,b-a) >>> to compute beta


          //Pushing αβγ into cDecide
          //cDecide.push_back(cABG());
          //cDecide[c] = {cAlfa, cBeta, cGamma};
          //cout << c << endl;


          evaluator.multiply_inplace(tmpC2,tmpC1);//Alfa
          cAlfa = tmpC2;
          evaluator.multiply_inplace(tmpC3,tmpC1);//Beta
          evaluator.negate_inplace(tmpC3);//Beta must be negate.
          cBeta = tmpC3;
          //decryptor.decrypt(tmpC2, p);
          //cout << encoder.decode_int64(p) << endl;
          //decryptor.decrypt(tmpC3, p);
          //cout << encoder.decode_int64(p) << endl;
          evaluator.multiply_inplace(tmpC1,tmpC1);
          evaluator.negate_inplace(tmpC2);
          evaluator.negate_inplace(tmpC3);
          evaluator.add_inplace(tmpC1,tmpC2);
          evaluator.add_inplace(tmpC1,tmpC3);//Gamma
          cGamma = tmpC1;


          //pRnd = encoder.encode(1 + std::rand()/((RAND_MAX + 1u)/100));
          //encryptor.encrypt(pRnd, cRnd);
          //evaluator.multiply_inplace(cBeta, cRnd);
          //evaluator.multiply_plain_inplace(cAlfa, pRnd);
          //pRnd = encoder.encode(1 + std::rand()/((RAND_MAX + 1u)/100));
          //encryptor.encrypt(pRnd, cRnd);
          //evaluator.multiply_inplace(cBeta, cRnd);
          //evaluator.multiply_plain_inplace(cBeta, pRnd);
          //pRnd = encoder.encode(1 + std::rand()/((RAND_MAX + 1u)/100));
          //encryptor.encrypt(pRnd, cRnd);
          //evaluator.multiply_inplace(cBeta, cRnd);
          //evaluator.multiply_plain_inplace(cGamma, pRnd);


          decryptor.decrypt(cAlfa, tmpP);
          iAlfa = encoder.decode_int64(tmpP);
          decryptor.decrypt(cBeta, tmpP);
          iBeta = encoder.decode_int64(tmpP);
          decryptor.decrypt(cGamma, tmpP);
          iGamma = encoder.decode_int64(tmpP);
//cout << iAlfa << " @@ " << iBeta << " @@ " << iGamma << endl;
          if (iAlfa>=0 && iBeta>=0 && iGamma>=0){
            flag++;
          }

          //decryptor.decrypt(tmpC1, p);
          //cout << encoder.decode_int64(p) << endl;

          c++;  //Prepare for next cDecide
         /*rasoul
      	  pRnd = encoder.encode(1 + std::rand()/((RAND_MAX + 1u)/100));
         //encryptor.encrypt(pRnd, cRnd);
          //evaluator.multiply_inplace(cAlfa, cRnd);
          evaluator.multiply_plain_inplace(cAlfa, pRnd);

          pRnd = encoder.encode(1 + std::rand()/((RAND_MAX + 1u)/100));
          //encryptor.encrypt(pRnd, cRnd);
          //evaluator.multiply_inplace(cBeta, cRnd);
          evaluator.multiply_plain_inplace(cBeta, pRnd);

          pRnd = encoder.encode(1 + std::rand()/((RAND_MAX + 1u)/100));
          //encryptor.encrypt(pRnd, cRnd);
          //evaluator.multiply_inplace(cGamma, cRnd);
          evaluator.multiply_plain_inplace(cGamma, pRnd);
          rasoul*/
          //Hasrem//decryptor.decrypt(cAlfa, tmpPRes);
          //Hasrem//cout << "α*r1 = " << encoder.decode_int64(tmpPRes);
          //Hasrem//decryptor.decrypt(cBeta, tmpPRes);
          //Hasrem//cout << "   β*r2 = " << encoder.decode_int64(tmpPRes);
          //Hasrem//decryptor.decrypt(cGamma, tmpPRes);
          //Hasrem//cout << "   γ*r3 = " << encoder.decode_int64(tmpPRes) << endl;

        }

        flags[q] = (double)flag/c;
        //cout << "Flag counter for query point q[" << q  << "] = "<< (double)flag/c << endl;
        //cout << "Next query point" << endl;

        //Hasrem//cout << c << endl;
/*

        for (int f=0; f<c; f++){
          decryptor.decrypt(cDecide[f].alfa, tmpP);
          iAlfa = encoder.decode_int64(tmpP);
          decryptor.decrypt(cDecide[f].beta, tmpP);
          iBeta = encoder.decode_int64(tmpP);
          decryptor.decrypt(cDecide[f].gamma, tmpP);
          iGamma = encoder.decode_int64(tmpP);
//cout << iAlfa << " @@ " << iBeta << " @@ " << iGamma << endl;
          if (iAlfa>=0 && iBeta>=0 && iGamma>=0){
            flag ++;

          }
        }*/
      }//End of loop for query point(s).
      /////////////////////////////////////////////////////////////////////////////////////////////

      cout << "Time taken for " << argv[1] << ", " << argv[2] << ", " << argv[3] << ": " << (double)(clock() - tStart)/CLOCKS_PER_SEC << endl;
      //for(int q=0; q<qrySize; q++) cout << "q[" << q << "] = " << flags[q] << endl;
      vector<cPoint>().swap(cDS);
      vector<cPoint>().swap(cQry);
      //vector<Ciphertext>().swap(cDets);
      vector<cABG>().swap(cDecide);
      tmpC1.release();tmpC2.release();tmpC3.release();
      cAlfa.release();cBeta.release();cGamma.release();
      tmpP.release(); pRnd.release();


return 0;
}

void print_parameters(shared_ptr<SEALContext> context)
{
    // Verify parameters
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    /*
    Which scheme are we using?
    */
    string scheme_name;
    switch (context_data.parms().scheme())
    {
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }

    cout << "/ Encryption parameters:" << endl;
    cout << "| scheme: " << scheme_name << endl;
    cout << "| poly_modulus_degree: " <<
        context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "| coeff_modulus size: " << context_data.
        total_coeff_modulus_bit_count() << " bits" << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV)
    {
        cout << "| plain_modulus: " << context_data.
            parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: " << context_data.
        parms().noise_standard_deviation() << endl;
    cout << endl;
}

vector<fPoint> readDataFromFile(string dataPath, int n){
   vector<fPoint> tmpData;
   std::ifstream input(dataPath);
   if(errno){
     cerr << "Error in processing " << dataPath << " (" << strerror(errno) << ")." << endl;
     exit(0);
   }
  for (int i=0; i<n; i++){
    tmpData.push_back(fPoint());
    input >> tmpData[i].x >> tmpData[i].y;
    //cout << tmpData[i].x << " ** " << tmpData[i].y << endl;
   }
   input.close();
   return tmpData;
}

Ciphertext detCompute(Evaluator &eval, cPoint M, cPoint N)
{ // retrun Mx*Ny-Nx*My

  Ciphertext t1 = M.x;
  Ciphertext t2 = M.y;
  eval.multiply_inplace(t1, N.y);
  eval.multiply_inplace(t2, N.x);
  eval.sub_inplace(t1, t2);
  return t1;
}
Ciphertext detCompute(Evaluator &eval, cPoint A, cPoint B, cPoint C){

  eval.negate_inplace(A.x);
  eval.add_inplace(B.x,A.x);//Bx-Ax >>> Bx
  eval.negate_inplace(A.y);
  eval.add_inplace(C.y,A.y);//Cy-Ay >>> Cy
  eval.multiply_inplace(B.x,C.y);//(Bx-Ax)*(Cy-Ay) >>> Bx

  //eval.negate_inplace(A.x);
  eval.add_inplace(C.x,A.x);//Cx-Ax >>> Cx
  //eval.negate_inplace(A.y);
  eval.add_inplace(B.y, A.y);//By-Ay >>> By

  eval.multiply_inplace(B.y,C.x);//(Cx-Ax)*(By-Ay) >>> By


  eval.negate_inplace(B.y);
  eval.add_inplace(B.x,B.y);

  return B.x;
}
