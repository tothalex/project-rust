import {
  BLS,
  Fr,
  G1,
  G2,
  SecretKey,
  PublicKey,
  GT,
  Signature,
} from "./bls-helper";

/**
 * Đỗ Thị Huyền Trang!
 * Special thanks to you! You inspired me the create this algorithm.
 * To the appreciation, your name is used to create the base point to initialize accumlator
 */

export class BlockItem {
  blockIdx!: number;
  dataIdx!: number;
  blockProof!: Signature;
  chainProof!: Signature;
}

export class Block {
  blockIdx!: number;
  items!: BlockItem[];
  blockPK!: PublicKey;
  blockAcc!: Signature;
  chainHash!: Fr;
  chainPK!: PublicKey;
  chainAcc!: Signature;
  ledgerChainPK!: PublicKey;
}

export interface IProofCreator {
  addItem(hash: string): void;
  getBlockProof(): Block;
  getItemProof(dataIdx: number, hash: string): BlockItem;
}

export class Proofer {
  public static getBlockProofer(
    prvData: {
      blockIndex: number;
      chainHash: Fr;
      chainPK: PublicKey;
      chainAcc: Signature;
      ledgerChainPK: PublicKey;
    } | null,
    chainSK: SecretKey,
  ): IProofCreator {
    return new ProofCreator(prvData, chainSK);
  }

  public static createBlock(
    prvData: {
      blockIndex: number;
      chainHash: Fr;
      chainPK: PublicKey;
      chainAcc: Signature;
      ledgerChainPK: PublicKey;
    } | null,
    trxHashes: string[],
    chainSK: SecretKey,
  ): Block {
    /**
     * Đỗ Thị Huyền Trang!
     * Special thanks to you! You inspired me the create this algorithm.
     * To the appreciation, your name is used to create the base point to initialize accumlator
     */
    if (BLS.isDefault()) {
      const helperG1 = BLS.hashAndMapToG1("Đỗ Thị Huyền Trang");
      const helperG2 = BLS.GetGeneratorOfPublicKey().to(G2);

      if (!prvData) {
        const one = new Fr();
        one.setInt(1);
        const ledgerSK = new Fr();
        ledgerSK.setByCSPRNG();
        const ledgerPK = BLS.mul(helperG2, ledgerSK);

        prvData = {
          blockIndex: -1,
          chainHash: one,
          chainPK: BLS.mul(helperG2, BLS.inv(chainSK.to(Fr))).to(PublicKey),
          chainAcc: BLS.mul(
            BLS.mul(helperG1, ledgerSK),
            BLS.inv(chainSK.to(Fr)),
          ).to(Signature),
          ledgerChainPK: ledgerPK.to(PublicKey),
        };
      }

      const block = createBlockG2(
        prvData.blockIndex,
        prvData.chainHash,
        prvData.chainPK.to(G2),
        prvData.chainAcc.to(G1),
        prvData.ledgerChainPK.to(G2),
        trxHashes,
        chainSK.to(Fr),
        helperG1,
        helperG2,
      );

      return {
        blockIdx: block.blockIdx,
        items: block.items.map((item) => ({
          blockIdx: item.blockIdx,
          dataIdx: item.dataIdx,
          dataHashFr: item.dataHashFr,
          blockProof: item.blockProof.to(Signature),
          chainProof: item.chainProof.to(Signature),
        })),
        blockPK: block.blockPK.to(PublicKey),
        blockAcc: block.blockAcc.to(Signature),
        chainHash: block.chainHash,
        chainPK: block.chainPK.to(PublicKey),
        chainAcc: block.chainAcc.to(Signature),
        ledgerChainPK: block.ledgerChainPK.to(PublicKey),
      };
    } else {
      const helperG1 = BLS.GetGeneratorOfPublicKey().to(G1);
      const helperG2 = BLS.hashAndMapToG2("Đỗ Thị Huyền Trang");

      if (!prvData) {
        const one = new Fr();
        one.setInt(1);
        const ledgerSK = new Fr();
        ledgerSK.setByCSPRNG();
        const ledgerPK = BLS.mul(helperG1, ledgerSK);

        prvData = {
          blockIndex: -1,
          chainHash: one,
          chainPK: BLS.mul(helperG1, BLS.inv(chainSK.to(Fr))).to(PublicKey),
          chainAcc: BLS.mul(
            BLS.mul(helperG2, ledgerSK),
            BLS.inv(chainSK.to(Fr)),
          ).to(Signature),
          ledgerChainPK: ledgerPK.to(PublicKey),
        };
      }

      const block = createBlockG1(
        prvData.blockIndex,
        prvData.chainHash,
        prvData.chainPK.to(G1),
        prvData.chainAcc.to(G2),
        prvData.ledgerChainPK.to(G1),
        trxHashes,
        chainSK.to(Fr),
        helperG1,
        helperG2,
      );

      return {
        blockIdx: block.blockIdx,
        items: block.items.map((item) => ({
          blockIdx: item.blockIdx,
          dataIdx: item.dataIdx,
          dataHashFr: item.dataHashFr,
          blockProof: item.blockProof.to(Signature),
          chainProof: item.chainProof.to(Signature),
        })),
        blockPK: block.blockPK.to(PublicKey),
        blockAcc: block.blockAcc.to(Signature),
        chainHash: block.chainHash,
        chainPK: block.chainPK.to(PublicKey),
        chainAcc: block.chainAcc.to(Signature),
        ledgerChainPK: block.ledgerChainPK.to(PublicKey),
      };
    }
  }

  //Ellenőrzéasek:
  //blockPK = s*G2;
  //blockProof = blockAcc/(h+s)
  //chainProof = chainAcc/(h+r)
  //1: e(trxBlockProof, h*G2 + trxBlockPK)*e(-trxBlockAcc, G2) ?= 1 	//az adott H block proof-j oké-e (blockban van)
  //2: e(trxChainProof, h*G2 + trxChainPK)*e(-trxChainAcc, G2) 		//az adott H chain proof-ja oké-e ()
  //3: e(trxChainAcc, G2) ?= e(trxChainHash*G1, trxChainPK) 			//az adott blokk PRE ellenőrzés
  //4: e(actChainAcc, G2) ?= e(actChainHash*G1, actChainPK) 			//az aktuális blokk PRE ellenőrzés
  //5: e(trxChainProof * actChainHash/trxChainHash, h*r[x]*G2 + r[x+1]*G2)*e(-actChainAcc, G2) //az adott H chain proof-ja oké-e az aktuálissal
  //ahol r[x] az act és a trx blockIdx különbségénél lévő chainPK értéke.
  public static checkTrx(
    trxOrigHash: string,

    trxBlockProof: Signature,
    trxChainProof: Signature,

    trxBlockPK: PublicKey,
    trxBlockAcc: Signature,
    trxChainHash: Fr,
    trxChainPK: PublicKey,
    trxChainAcc: Signature,

    actChainHash: Fr,
    actChainPK: PublicKey,
    actChainAcc: Signature,

    firstChainPk: PublicKey,
    deltaChainPk: PublicKey,
    deltaNextChainPk: PublicKey,

    ledgerChainInitSig: Signature,
    ledgerChainGenesisHash: string,
  ): boolean {
    const ledgerChainGenesis = BLS.hashToFr(ledgerChainGenesisHash);
    if (ledgerChainGenesisHash === "") {
      ledgerChainGenesis.setInt(1);
    }
    /**
     * Đỗ Thị Huyền Trang!
     * Special thanks to you! You inspired me the create this algorithm.
     * To the appreciation, your name is used to create the base point to initialize accumlator
     */
    const gt_one = new GT();
    gt_one.setInt(1);
    if (BLS.isDefault()) {
      return checkTrxG2(
        trxOrigHash,
        trxBlockProof.to(G1),
        trxChainProof.to(G1),
        trxBlockPK.to(G2),
        trxBlockAcc.to(G1),
        trxChainHash,
        trxChainPK.to(G2),
        trxChainAcc.to(G1),
        actChainHash,
        actChainPK.to(G2),
        actChainAcc.to(G1),
        firstChainPk.to(G2),
        deltaChainPk.to(G2),
        deltaNextChainPk.to(G2),
        gt_one,
        BLS.mul(ledgerChainInitSig.to(G1), BLS.inv(ledgerChainGenesis)),
        BLS.GetGeneratorOfPublicKey().to(G2),
      );
    } else {
      return checkTrxG1(
        trxOrigHash,
        trxBlockProof.to(G2),
        trxChainProof.to(G2),
        trxBlockPK.to(G1),
        trxBlockAcc.to(G2),
        trxChainHash,
        trxChainPK.to(G1),
        trxChainAcc.to(G2),
        actChainHash,
        actChainPK.to(G1),
        actChainAcc.to(G2),
        firstChainPk.to(G1),
        deltaChainPk.to(G1),
        deltaNextChainPk.to(G1),
        gt_one,
        BLS.GetGeneratorOfPublicKey().to(G1),
        BLS.mul(ledgerChainInitSig.to(G2), BLS.inv(ledgerChainGenesis)),
      );
    }
  }

  public static getProofHash(hash: string): string {
    return BLS.hashToFr(hash).serializeToHexStr();
  }
}

class ProofCreatorG1 implements IProofCreator {
  constructor(
    private readonly chainSK: Fr,
    private blockIndex: number,
    private chainHash: Fr,
    private chainPK: G1,
    private chainAcc: G2,
    private ledgerChainPK: G1,
  ) {
    /**
     * Đỗ Thị Huyền Trang!
     * Special thanks to you! You inspired me the create this algorithm.
     * To the appreciation, your name is used to create the base point to initialize accumlator
     */
    this.helperG1 = BLS.GetGeneratorOfPublicKey().to(G1);
    this.helperG2 = BLS.hashAndMapToG2("Đỗ Thị Huyền Trang");

    this.blockSK = new Fr();
    this.blockSK.setByCSPRNG();
    this.blockPK = BLS.mul(this.helperG1, this.blockSK);

    this.blockHash = new Fr();
    this.blockHash.setInt(1);

    const initialRnd = new Fr();
    initialRnd.setByCSPRNG();
    this.blockAcc = BLS.mul(this.helperG2, initialRnd); //Initial Seed for accumlator
    initialRnd.clear();

    this.one = new Fr();
    this.one.setInt(1);
  }

  private isCreated = false;

  private readonly helperG1: G1;
  private readonly helperG2: G2;

  private readonly blockSK: Fr;
  private readonly blockPK: G1;
  private blockHash: Fr;
  private blockAcc: G2;
  private one: Fr;

  public addItem(hash: string): void {
    if (this.isCreated) {
      throw new Error("Blockproof already created, could not add more item!");
    }
    const itemHashFr = BLS.hashToFr(hash);
    this.blockHash = BLS.mul(this.blockHash, itemHashFr);
    this.blockAcc = BLS.mul(this.blockAcc, BLS.add(itemHashFr, this.blockSK));
  }

  public getBlockProof(): Block {
    if (!this.isCreated) {
      this.chainHash = BLS.mul(this.chainHash, this.blockHash);
      this.chainPK = BLS.mul(this.chainPK, this.chainSK);
      this.chainAcc = BLS.mul(
        this.chainAcc,
        BLS.mul(this.blockHash, this.chainSK),
      );
    }
    this.isCreated = true;
    return {
      blockIdx: this.blockIndex,
      blockPK: this.blockPK.to(PublicKey),
      blockAcc: this.blockAcc.to(Signature),
      chainHash: this.chainHash,
      chainPK: this.chainPK.to(PublicKey),
      chainAcc: this.chainAcc.to(Signature),
      ledgerChainPK: this.ledgerChainPK.to(PublicKey),
      items: [],
    };
  }

  public getItemProof(dataIdx: number, hash: string): BlockItem {
    if (!this.isCreated) {
      this.getBlockProof();
    }
    const itemHashFr = BLS.hashToFr(hash);
    const blockProof = BLS.mul(
      this.blockAcc,
      BLS.add(itemHashFr, this.blockSK).inv(),
    );
    const chainProof = BLS.mul(
      this.chainAcc,
      BLS.add(itemHashFr, this.chainSK).inv(),
    );
    return {
      blockIdx: this.blockIndex,
      dataIdx: dataIdx,
      blockProof: blockProof.to(Signature),
      chainProof: chainProof.to(Signature),
    };
  }
}

class ProofCreatorG2 implements IProofCreator {
  constructor(
    private readonly chainSK: Fr,
    private blockIndex: number,
    private chainHash: Fr,
    private chainPK: G2,
    private chainAcc: G1,
    private ledgerChainPK: G2,
  ) {
    /**
     * Đỗ Thị Huyền Trang!
     * Special thanks to you! You inspired me the create this algorithm.
     * To the appreciation, your name is used to create the base point to initialize accumlator
     */
    this.helperG1 = BLS.hashAndMapToG1("Đỗ Thị Huyền Trang");
    this.helperG2 = BLS.GetGeneratorOfPublicKey().to(G2);

    this.blockSK = new Fr();
    this.blockSK.setByCSPRNG();
    this.blockPK = BLS.mul(this.helperG2, this.blockSK);

    this.blockHash = new Fr();
    this.blockHash.setInt(1);

    const initialRnd = new Fr();
    initialRnd.setByCSPRNG();
    this.blockAcc = BLS.mul(this.helperG1, initialRnd); //Initial Seed for accumlator
    initialRnd.clear();

    this.one = new Fr();
    this.one.setInt(1);
  }

  private isCreated = false;

  private readonly helperG1: G1;
  private readonly helperG2: G2;

  private readonly blockSK: Fr;
  private readonly blockPK: G2;
  private blockHash: Fr;
  private blockAcc: G1;
  private one: Fr;

  public addItem(hash: string): void {
    if (this.isCreated) {
      throw new Error("Blockproof already created, could not add more item!");
    }
    const itemHashFr = BLS.hashToFr(hash);
    this.blockHash = BLS.mul(this.blockHash, itemHashFr);
    this.blockAcc = BLS.mul(this.blockAcc, BLS.add(itemHashFr, this.blockSK));
  }

  public getBlockProof(): Block {
    if (!this.isCreated) {
      this.chainHash = BLS.mul(this.chainHash, this.blockHash);
      this.chainPK = BLS.mul(this.chainPK, this.chainSK);
      this.chainAcc = BLS.mul(
        this.chainAcc,
        BLS.mul(this.blockHash, this.chainSK),
      );
    }
    this.isCreated = true;
    return {
      blockIdx: this.blockIndex,
      blockPK: this.blockPK.to(PublicKey),
      blockAcc: this.blockAcc.to(Signature),
      chainHash: this.chainHash,
      chainPK: this.chainPK.to(PublicKey),
      chainAcc: this.chainAcc.to(Signature),
      ledgerChainPK: this.ledgerChainPK.to(PublicKey),
      items: [],
    };
  }

  public getItemProof(dataIdx: number, hash: string): BlockItem {
    if (!this.isCreated) {
      this.getBlockProof();
    }
    const itemHashFr = BLS.hashToFr(hash);
    const blockProof = BLS.mul(
      this.blockAcc,
      BLS.add(itemHashFr, this.blockSK).inv(),
    );
    const chainProof = BLS.mul(
      this.chainAcc,
      BLS.add(itemHashFr, this.chainSK).inv(),
    );
    return {
      blockIdx: this.blockIndex,
      dataIdx: dataIdx,
      blockProof: blockProof.to(Signature),
      chainProof: chainProof.to(Signature),
    };
  }
}

class ProofCreator implements IProofCreator {
  constructor(
    prvData: {
      blockIndex: number;
      chainHash: Fr;
      chainPK: PublicKey;
      chainAcc: Signature;
      ledgerChainPK: PublicKey;
    } | null,
    chainSK: SecretKey,
  ) {
    //
    /**
     * Đỗ Thị Huyền Trang!
     * Special thanks to you! You inspired me the create this algorithm.
     * To the appreciation, your name is used to create the base point to initialize accumlator
     */
    if (BLS.isDefault()) {
      if (!prvData) {
        const helperG1 = BLS.hashAndMapToG1("Đỗ Thị Huyền Trang");
        const helperG2 = BLS.GetGeneratorOfPublicKey().to(G2);
        const one = new Fr();
        one.setInt(1);
        const ledgerSK = new Fr();
        ledgerSK.setByCSPRNG();
        const ledgerPK = BLS.mul(helperG2, ledgerSK);

        prvData = {
          blockIndex: -1,
          chainHash: one,
          chainPK: BLS.mul(helperG2, BLS.inv(chainSK.to(Fr))).to(PublicKey),
          chainAcc: BLS.mul(
            BLS.mul(helperG1, ledgerSK),
            BLS.inv(chainSK.to(Fr)),
          ).to(Signature),
          ledgerChainPK: ledgerPK.to(PublicKey),
        };
      }
      this.proofCreator = new ProofCreatorG2(
        chainSK.to(Fr),
        prvData.blockIndex + 1,
        prvData.chainHash,
        prvData.chainPK.to(G2),
        prvData.chainAcc.to(G1),
        prvData.ledgerChainPK.to(G2),
      );
    } else {
      if (!prvData) {
        const helperG1 = BLS.GetGeneratorOfPublicKey().to(G1);
        const helperG2 = BLS.hashAndMapToG2("Đỗ Thị Huyền Trang");

        const one = new Fr();
        one.setInt(1);
        const ledgerSK = new Fr();
        ledgerSK.setByCSPRNG();
        const ledgerPK = BLS.mul(helperG1, ledgerSK);

        prvData = {
          blockIndex: -1,
          chainHash: one,
          chainPK: BLS.mul(helperG1, BLS.inv(chainSK.to(Fr))).to(PublicKey),
          chainAcc: BLS.mul(
            BLS.mul(helperG2, ledgerSK),
            BLS.inv(chainSK.to(Fr)),
          ).to(Signature),
          ledgerChainPK: ledgerPK.to(PublicKey),
        };
      }

      this.proofCreator = new ProofCreatorG1(
        chainSK.to(Fr),
        prvData.blockIndex + 1,
        prvData.chainHash,
        prvData.chainPK.to(G1),
        prvData.chainAcc.to(G2),
        prvData.ledgerChainPK.to(G1),
      );
    }
  }

  private readonly proofCreator: IProofCreator;

  public addItem(hash: string): void {
    this.proofCreator.addItem(hash);
  }

  public getBlockProof(): Block {
    return this.proofCreator.getBlockProof();
  }

  public getItemProof(dataIdx: number, hash: string): BlockItem {
    return this.proofCreator.getItemProof(dataIdx, hash);
  }
}

class BlockItemG2 {
  blockIdx!: number;
  dataIdx!: number;
  dataHashFr!: Fr;
  blockProof!: G1;
  chainProof!: G1;
}

class BlockG2 {
  blockIdx!: number;
  items!: BlockItemG2[];
  blockPK!: G2;
  blockAcc!: G1;
  chainHash!: Fr;
  chainPK!: G2;
  chainAcc!: G1;
  ledgerChainPK!: G2;
}

class BlockItemG1 {
  blockIdx!: number;
  dataIdx!: number;
  dataHashFr!: Fr;
  blockProof!: G2;
  chainProof!: G2;
}

class BlockG1 {
  blockIdx!: number;
  items!: BlockItemG1[];
  blockPK!: G1;
  blockAcc!: G2;
  chainHash!: Fr;
  chainPK!: G1;
  chainAcc!: G2;
  ledgerChainPK!: G1;
}

function createBlockG1(
  prvBlockIndex: number,
  prvChainHash: Fr,
  prvChainPK: G1,
  prvChainAcc: G2,
  prvLedgerChainPK: G1,
  trxHashes: string[],
  chainSK: Fr,
  helperG1: G1,
  helperG2: G2,
): BlockG1 {
  const blockSK = new Fr();
  blockSK.setByCSPRNG();
  const blockPK = BLS.mul(helperG1, blockSK);

  //Calculate G1 point
  const initialRnd = new Fr();
  initialRnd.setByCSPRNG();
  const blockAcc = BLS.mul(helperG2, initialRnd); //Initial Seed for accumlator
  initialRnd.clear();

  //{ idx: 0, trx: trx1, hash: new Fr(), chainProof: new G1(), blockProof: new G1() }
  const actBlockIndex = prvBlockIndex + 1;

  const newBlock: BlockG1 = {
    blockIdx: actBlockIndex,
    items: trxHashes.map((item, index): BlockItemG1 => {
      return {
        blockIdx: actBlockIndex,
        dataIdx: index,
        dataHashFr: BLS.hashToFr(item),
        blockProof: new G2(),
        chainProof: new G2(),
      };
    }),
    blockPK: blockPK,
    blockAcc: blockAcc,
    chainHash: prvChainHash,
    chainPK: prvChainPK.clone<G1>(), //r-rel szorozni
    chainAcc: prvChainAcc.clone<G2>(), //r-rel és datavál szorozni
    ledgerChainPK: prvLedgerChainPK,
  };

  //calculate accumlator and preImage and preImageAccu
  let blockHash = new Fr();
  blockHash.setInt(1);
  for (let i = 0; i < newBlock.items.length; i++) {
    //itt kéne insertálni a blockItemeket...
    //data2[i].itemHashFr = BLS.hashToFr(newBlock.items[i].itemHash);
    blockHash = BLS.mul(blockHash, newBlock.items[i].dataHashFr);
    newBlock.blockAcc = BLS.mul(
      newBlock.blockAcc,
      BLS.add(newBlock.items[i].dataHashFr, blockSK),
    );
  }
  newBlock.chainHash = BLS.mul(newBlock.chainHash, blockHash);
  newBlock.chainPK = BLS.mul(newBlock.chainPK, chainSK);
  newBlock.chainAcc = BLS.mul(newBlock.chainAcc, BLS.mul(blockHash, chainSK));

  //Generate proofs for items, ez mehetne párhuzamosan is...
  for (let i = 0; i < newBlock.items.length; i++) {
    newBlock.items[i].blockProof = BLS.mul(
      newBlock.blockAcc,
      BLS.add(newBlock.items[i].dataHashFr, blockSK).inv(),
    );
    newBlock.items[i].chainProof = BLS.mul(
      newBlock.chainAcc,
      BLS.add(newBlock.items[i].dataHashFr, chainSK).inv(),
    );
  }

  blockSK.clear();
  return newBlock;
}

function createBlockG2(
  prvBlockIndex: number,
  prvChainHash: Fr,
  prvChainPK: G2,
  prvChainAcc: G1,
  prvLedgerChainPK: G2,
  trxHashes: string[],
  chainSK: Fr,
  helperG1: G1,
  helperG2: G2,
): BlockG2 {
  const blockSK = new Fr();
  blockSK.setByCSPRNG();
  const blockPK = BLS.mul(helperG2, blockSK);

  //Calculate G1 point
  const initialRnd = new Fr();
  initialRnd.setByCSPRNG();
  const blockAccG1 = BLS.mul(helperG1, initialRnd); //Initial Seed for accumlator
  initialRnd.clear();

  //{ idx: 0, trx: trx1, hash: new Fr(), chainProof: new G1(), blockProof: new G1() }
  const actBlockIndex = prvBlockIndex + 1;

  const newBlock: BlockG2 = {
    blockIdx: actBlockIndex,
    items: trxHashes.map((item, index): BlockItemG2 => {
      return {
        blockIdx: actBlockIndex,
        dataIdx: index,
        dataHashFr: BLS.hashToFr(item),
        blockProof: new G1(),
        chainProof: new G1(),
      };
    }),
    blockPK: blockPK,
    blockAcc: blockAccG1.clone<G1>(),
    chainHash: prvChainHash,
    chainPK: prvChainPK.clone<G2>(), //r-rel szorozni
    chainAcc: prvChainAcc.clone<G1>(), //r-rel és datavál szorozni
    ledgerChainPK: prvLedgerChainPK.clone<G2>(),
  };

  //calculate accumlator and preImage and preImageAccu
  let blockHash = new Fr();
  blockHash.setInt(1);
  for (let i = 0; i < newBlock.items.length; i++) {
    //itt kéne insertálni a blockItemeket...
    //data2[i].itemHashFr = BLS.hashToFr(newBlock.items[i].itemHash);
    blockHash = BLS.mul(blockHash, newBlock.items[i].dataHashFr);
    newBlock.blockAcc = BLS.mul(
      newBlock.blockAcc,
      BLS.add(newBlock.items[i].dataHashFr, blockSK),
    );
  }
  newBlock.chainHash = BLS.mul(newBlock.chainHash, blockHash);
  newBlock.chainPK = BLS.mul(newBlock.chainPK, chainSK);
  newBlock.chainAcc = BLS.mul(newBlock.chainAcc, BLS.mul(blockHash, chainSK));

  //Generate proofs for items, ez mehetne párhuzamosan is...
  for (let i = 0; i < newBlock.items.length; i++) {
    newBlock.items[i].blockProof = BLS.mul(
      newBlock.blockAcc,
      BLS.add(newBlock.items[i].dataHashFr, blockSK).inv(),
    );
    newBlock.items[i].chainProof = BLS.mul(
      newBlock.chainAcc,
      BLS.add(newBlock.items[i].dataHashFr, chainSK).inv(),
    );
  }

  blockSK.clear();
  return newBlock;
}

function checkTrxG1(
  trxOrigHash: string,

  trxBlockProof: G2,
  trxChainProof: G2,

  trxBlockPK: G1,
  trxBlockAcc: G2,
  trxChainHash: Fr,
  trxChainPK: G1,
  trxChainAcc: G2,

  actChainHash: Fr,
  actChainPK: G1,
  actChainAcc: G2,

  firstChainPk: G1,
  deltaChainPk: G1,
  deltaNextChainPk: G1,

  gt_one: GT,
  helperG1: G1, //Generator of PublicKey
  helperG2: G2,
): boolean {
  const trxHash = BLS.hashToFr(trxOrigHash);
  // const gt_one = new GT();
  // gt_one.setInt(1);

  //1: e(trxBlockProof, h*G2 + trxBlockPK)*e(-trxBlockAcc, G2) ?= 1 	//az adott H block proof-j oké-e (blockban van)
  const verify1_e1 = BLS.pairing(
    BLS.add(BLS.mul(helperG1, trxHash), trxBlockPK),
    trxBlockProof,
  );
  const verify1_e2 = BLS.pairing(helperG1, BLS.neg(trxBlockAcc));
  const verify1 = BLS.mul(verify1_e1, verify1_e2).isEqual(gt_one);
  if (!verify1) {
    return false;
  }

  //2: e(trxChainProof, h*G2 + zeroChainPk)*e(-trxChainAcc, G2) 		//az adott H chain proof-ja oké-e ()
  const verify2_e1 = BLS.pairing(
    BLS.add(BLS.mul(helperG1, trxHash), firstChainPk),
    trxChainProof,
  );
  const verify2_e2 = BLS.pairing(helperG1, BLS.neg(trxChainAcc));
  const verify2 = BLS.mul(verify2_e1, verify2_e2).isEqual(gt_one);
  if (!verify2) {
    return false;
  }

  //3: e(trxChainAcc, G2) ?= e(trxChainHash*G1, trxChainPK) 			//az adott blokk PRE ellenőrzés
  const verify3_e1 = BLS.pairing(helperG1, trxChainAcc);
  const verify3_e2 = BLS.pairing(trxChainPK, BLS.mul(helperG2, trxChainHash));
  const verify3 = verify3_e1.isEqual(verify3_e2);
  if (!verify3) {
    return false;
  }

  //4: e(actChainAcc, G2) ?= e(actChainHash*G1, actChainPK) 			//az aktuális blokk PRE ellenőrzés
  const verify4_e1 = BLS.pairing(helperG1, actChainAcc);
  const verify4_e2 = BLS.pairing(actChainPK, BLS.mul(helperG2, actChainHash));
  const verify4 = verify4_e1.isEqual(verify4_e2);
  if (!verify4) {
    return false;
  }

  //5: e(trxChainProof * actChainHash/trxChainHash, h*r[x]*G2 + r[x+1]*G2)*e(-actChainAcc, G2) //az adott H chain proof-ja oké-e az aktuális blokkal
  //ahol r[x] az act és a trx blockIdx különbségénél lévő chainPK értéke.
  const deltaChainHash = BLS.div(actChainHash, trxChainHash);
  const verify5_e1 = BLS.pairing(
    BLS.add(BLS.mul(deltaChainPk, trxHash), deltaNextChainPk),
    BLS.mul(trxChainProof, deltaChainHash),
  );
  const verify5_e2 = BLS.pairing(helperG1, BLS.neg(actChainAcc));
  const verify5 = BLS.mul(verify5_e1, verify5_e2).isEqual(gt_one);
  if (!verify5) {
    return false;
  }

  return true;
}

function checkTrxG2(
  trxOrigHash: string,

  trxBlockProof: G1,
  trxChainProof: G1,

  trxBlockPK: G2,
  trxBlockAcc: G1,
  trxChainHash: Fr,
  trxChainPK: G2,
  trxChainAcc: G1,

  actChainHash: Fr,
  actChainPK: G2,
  actChainAcc: G1,

  firstChainPk: G2,
  deltaChainPk: G2,
  deltaNextChainPk: G2,

  gt_one: GT,
  helperG1: G1,
  helperG2: G2, //Generator of PublicKey
): boolean {
  const trxHash = BLS.hashToFr(trxOrigHash);

  //1: e(trxBlockProof, h*G2 + trxBlockPK)*e(-trxBlockAcc, G2) ?= 1 	//az adott H block proof-j oké-e (blockban van)
  const verify1_e1 = BLS.pairing(
    trxBlockProof,
    BLS.add(BLS.mul(helperG2, trxHash), trxBlockPK),
  );
  const verify1_e2 = BLS.pairing(BLS.neg(trxBlockAcc), helperG2);
  const verify1 = BLS.mul(verify1_e1, verify1_e2).isEqual(gt_one);
  if (!verify1) {
    return false;
  }

  //2: e(trxChainProof, h*G2 + zeroChainPk)*e(-trxChainAcc, G2) 		//az adott H chain proof-ja oké-e ()
  const verify2_e1 = BLS.pairing(
    trxChainProof,
    BLS.add(BLS.mul(helperG2, trxHash), firstChainPk),
  );
  const verify2_e2 = BLS.pairing(BLS.neg(trxChainAcc), helperG2);
  const verify2 = BLS.mul(verify2_e1, verify2_e2).isEqual(gt_one);
  if (!verify2) {
    return false;
  }

  //3: e(trxChainAcc, G2) ?= e(trxChainHash*G1, trxChainPK) 			//az adott blokk PRE ellenőrzés
  const verify3_e1 = BLS.pairing(trxChainAcc, helperG2);
  const verify3_e2 = BLS.pairing(BLS.mul(helperG1, trxChainHash), trxChainPK);
  const verify3 = verify3_e1.isEqual(verify3_e2);
  if (!verify3) {
    return false;
  }

  //4: e(actChainAcc, G2) ?= e(actChainHash*G1, actChainPK) 			//az aktuális blokk PRE ellenőrzés
  const verify4_e1 = BLS.pairing(actChainAcc, helperG2);
  const verify4_e2 = BLS.pairing(BLS.mul(helperG1, actChainHash), actChainPK);
  const verify4 = verify4_e1.isEqual(verify4_e2);
  if (!verify4) {
    return false;
  }

  //5: e(trxChainProof * actChainHash/trxChainHash, h*r[x]*G2 + r[x+1]*G2)*e(-actChainAcc, G2) //az adott H chain proof-ja oké-e az aktuális blokkal
  //ahol r[x] az act és a trx blockIdx különbségénél lévő chainPK értéke.
  const deltaChainHash = BLS.div(actChainHash, trxChainHash);
  const verify5_e1 = BLS.pairing(
    BLS.mul(trxChainProof, deltaChainHash),
    BLS.add(BLS.mul(deltaChainPk, trxHash), deltaNextChainPk),
  );
  const verify5_e2 = BLS.pairing(BLS.neg(actChainAcc), helperG2);
  const verify5 = BLS.mul(verify5_e1, verify5_e2).isEqual(gt_one);
  if (!verify5) {
    return false;
  }

  return true;
}
