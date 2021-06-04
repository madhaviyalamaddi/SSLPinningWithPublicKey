//
//  ViewController.swift
//  SSLPinningWithPublicKey
//
//  Created by madhavi.yalamaddi on 05/06/21.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        SSLPinningManager.shared.callRemoteService(urlString: "https://www.google.com") { (response) in
            print(response)
        }
        // Do any additional setup after loading the view.
    }


}

